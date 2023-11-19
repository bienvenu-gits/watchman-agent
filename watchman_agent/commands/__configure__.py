import configparser
import os

import yaml


def update_config_with_nested(config, updated_config):
    if config:
        for key, value in updated_config.items():
            if key in config and isinstance(config[key], dict) and isinstance(value, dict):
                # Recursively update nested dictionaries
                update_config_with_nested(config[key], value)
            elif key in config and isinstance(config[key], list) and isinstance(value, list):
                # Extend existing lists with new values
                config[key].extend(value)
            else:
                # Update or add a new key-value pair
                config[key] = value


class IniFileConfiguration:
    _instance = None

    def __new__(cls, config_file_path=None):
        if not config_file_path:
            config_file_path = 'config.ini'

        if cls._instance is None:
            cls._instance = super(IniFileConfiguration, cls).__new__(cls)
            cls._instance.config = configparser.ConfigParser()
            cls._instance.config_file_path = config_file_path
            cls._instance.load_config()
        return cls._instance

    def load_config(self):
        if self.config_file_path is not None and os.path.exists(self.config_file_path):
            self.config.read(self.config_file_path)
        else:
            with open(self.config_file_path, 'w') as config_file:
                self.config.write(config_file)

    def get_value(self, section, key, default=None):
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def set_value(self, section, key, value):
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, value)
        self.save_config_to_file()

    def ensure_update(self, old_config, new_config):
        return NotImplementedError

    def save_config_to_file(self):
        with open(self.config_file_path, 'w') as configfile:
            self.config.write(configfile)


class YamlFileConfiguration:
    _instance = None

    def __new__(cls, config_file_path=None):
        if not config_file_path:
            config_file_path = "config.yml"

        if cls._instance is None:
            cls._instance = super(YamlFileConfiguration, cls).__new__(cls)
            cls._instance.config = {}
            cls._instance.config_file_path = config_file_path
            cls._instance.load_config()
        return cls._instance

    def load_config(self):
        if self.config_file_path is not None and os.path.exists(self.config_file_path):
            with open(self.config_file_path, 'r') as yaml_file:
                self.config = yaml.safe_load(yaml_file)
        else:
            # If it doesn't exist, create an empty YAML file
            with open(self.config_file_path, 'w') as yaml_file:
                yaml.dump({}, yaml_file, default_flow_style=False)

    def get_value(self, *keys, default=None):
        try:
            config_section = self.config
            for key in keys:
                config_section = config_section.get(key, {})
            return config_section
        except (AttributeError, KeyError):
            return default

    def set_value(self, *keys, value):
        config_section = self.config
        for key in keys[:-1]:
            config_section = config_section.setdefault(key, {})
        config_section[keys[-1]] = value
        self.save_config_to_file()

    def ensure_update(self, old_config, new_config):
        if new_config:
            update_config_with_nested(old_config, new_config)

        try:
            with open(self.config_file_path, 'w') as yaml_file:
                yaml.dump(old_config, yaml_file, default_flow_style=False)
            print(f"Configs successfully updated in '{yaml_file}'.")
        except yaml.YAMLError as e:
            print(f"Cannot update config file. {e}")

    def save_config_to_file(self):
        if self.config and self.config_file_path:
            with open(self.config_file_path, 'w') as yaml_file:
                yaml.dump(self.config, yaml_file, default_flow_style=False)


class Configuration:
    @staticmethod
    def create(config_file_path="config.yml"):
        if config_file_path and config_file_path.endswith('.yml'):
            return YamlFileConfiguration(config_file_path)
        else:
            return IniFileConfiguration(config_file_path)
