from configparser import ConfigParser
config = ConfigParser()


class ConfigNotFound(Exception):
    """
    Thrown when the configuration cannot be found
    """
    def __init__(self, locations):
        """
        :param message: A more specific error message
        """
        msg = "Config was not found in any of the following locations: {}".format(locations)
        super(ConfigNotFound, self).__init__(msg)


paths = ['config.cfg', '/etc/dynamite/dynamite_sdk/config.cfg']

config.read(paths)
if 'AUTHENTICATION' not in config:
    raise ConfigNotFound(paths)
