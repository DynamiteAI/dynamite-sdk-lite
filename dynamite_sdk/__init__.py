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

found = False
for path in paths:
    try:
        config.read(path)
        found = True
        break
    except FileNotFoundError:
        pass
if not found:
    raise ConfigNotFound(paths)

