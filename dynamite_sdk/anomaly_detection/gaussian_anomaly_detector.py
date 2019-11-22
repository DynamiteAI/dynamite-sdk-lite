from sklearn.base import BaseEstimator, TransformerMixin
import numpy as np
import math
import scipy.stats as stats
from typing import TypeVar


GaussianAnomalyDetectorClassType = TypeVar('GaussianAnomalyDetectorClassType', bound='GaussianAnomalyDetector')


class GaussianAnomalyDetector(BaseEstimator, TransformerMixin):
    """
    Anomaly Detector based on the probability distribution
    """

    def f(self, mu, sig, x):
        return np.e**(-(((x - mu) / sig)**2) / 2) / (sig * (np.pi * 2) ** 0.5)

    def __init__(self, contamination=0.01, log_transform=False):
        """
        :param contamination: float in (0., 0.5), optional (default=0.01)
        The amount of contamination of the data set, i.e. the proportion
        of outliers in the data set. Used when fitting to define the threshold
        on the decision function.
        :param log_transform: If True then dataset will log (to base e) transformed
        """
        self.mean_dict = {}
        self.std_dict = {}
        self.contamination = contamination
        self.reason = []
        self.log_transform = log_transform
        self.product_pd = []
        self.cutoff_threshold = 0.00001
        self.epsilon = 1e-100 # to handle zero standard deviation

    def get_mean(self) -> dict:
        """
        :return: a dictionary with key:feature name value: mean
        """
        return self.mean_dict

    def get_std(self) -> dict:
        """
        :return: a dictionary with key:feature name value: standard deviation
        """
        return self.std_dict

    def get_reason(self) -> list:
        """
        returns reason associated with the anomalous entities
        :return: a list containing the reasons for all entities passed to predict function
        """
        return self.reason

    def fit(self, X, y=None) -> GaussianAnomalyDetectorClassType:
        """
        Fit estimator.
        :param X: array-like or sparse matrix, shape (n_samples, n_features)
        The input samples. Use ``dtype=np.float32`` for maximum
        efficiency. Sparse matrices are also supported, use sparse
        ``csc_matrix`` for maximum efficiency.
        :return: self : object
        Returns self.
        """
        if self.log_transform:
            X = self._transform_data(X)
        for col in X.columns:
            self.mean_dict[col] = np.mean(X[col])
            self.std_dict[col] = np.std(X[col]) + self.epsilon # to handle zero standard deviation
        self._compute_cutoff_threshold(X)
        return self

    def predict(self, X) -> list:
        """
        Predict if a particular sample is an outlier or not.
        :param X: array-like or sparse matrix, shape (n_samples, n_features)
        The input samples. Use ``dtype=np.float32`` for maximum
        efficiency. Sparse matrices are also supported, use sparse
        ``csc_matrix`` for maximum efficiency.
        :return: an array, shape (n_samples,)
        For each observations, tells whether or not (1 or 0) it should
        be considered as an anomaly according to the fitted model.
        """
        if self.log_transform:
            X = self._transform_data(X)
        predictions = self._compute_score(X)

        return predictions.tolist()

    def _compute_cutoff_threshold(self, X):
        """
        compute the probability cutoff threshold based the contamination
        :param X: pandas dataframe
        """
        cutoff_index = int(len(X) * self.contamination)
        self._compute_score(X)
        sorted_pd = np.sort(self.product_pd)
        self.cutoff_threshold = sorted_pd[cutoff_index]

    def _transform_data(self, data):
        """
        log transform the data
        :param data: pandas dataframe
        :return: pandas dataframe
        """
        return np.log(data + 1)

    def _compute_score(self, X) -> np.array:
        """
        computes score using probability density function and reason based on the lowest probability among
        all the features
        :param X:
        :return: numpy array of 1 (anomaly) and 0 (normal)
        """
        i = 0
        column_names = np.array(X.columns)
        mat = []
        for column_values in X.values.T:
            try:
                mu = self.get_mean()[column_names[i]]
                sigma = self.get_std()[column_names[i]]
                fi = self.f(mu, sigma, column_values)
                mat.append(fi)
                i+=1
            except KeyError as error:
                print('Column {0} not found in the model'.format(error))
                raise

        pdf_mat = np.array(mat).T
        reasons_for_min_prob = column_names[np.argmin(pdf_mat, axis=1)]
        self.product_pd = np.product(pdf_mat, axis=1)

        scores = self.product_pd < self.cutoff_threshold

        self.reason = [reason if score else 'not_anomalous' for reason, score in zip(reasons_for_min_prob, scores)]

        return scores.astype(int)
