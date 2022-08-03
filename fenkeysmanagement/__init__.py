from __future__ import annotations

import sys
import os
import re
import argparse
import json
import secrets
import dataclasses
from typing import Optional, List

from tabulate import tabulate


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


class CollisionsList(list):
    def get(self, field, value):
        for item in self:
            if getattr(item, field) == value:
                return item
        return None

    def update(self, search_field, search_value, field, value):
        for item in self:
            if getattr(item, search_field) == search_value:
                setattr(item, field, value)
                return True
        raise ValueError('No value {0} found for field {1}'.format(search_value, search_field))

    def contains(self, field, value):
        for item in self:
            if getattr(item, field) == value:
                return True
        return False

    def append(self, other, field):
        for item in self:
            if getattr(other, field) == getattr(item, field):
                raise ValueError('Value already added: {0}'.format(other))
        super().append(other)


class KeyManagerException(Exception):
    pass


class KeyManagerActionException(Exception):
    pass


@dataclasses.dataclass
class Key:
    id: str
    key: str
    comment: str
    revoked: bool


@dataclasses.dataclass
class KeyManager:
    keys: CollisionsList[Key]

    def __init__(self, keyfile="keyfile.json", *args, **kargs):
        self.keys = CollisionsList()
        self.keyfile = keyfile
        self._load_keyfile()
        super().__init__()

    def _load_keyfile(self):
        keys_json = self._read_keyfile()
        for key in keys_json:
            self.keys.append(Key(**key), 'id')

    def _save_key(self):
        self._write_keyfile()

    def _revoke_key(self, key, value):
        self.keys.update(key, value, 'revoked', True)
        self._write_keyfile()

    def _read_keyfile(self):
        data = {}
        if os.path.isfile(self.keyfile):
            with open(self.keyfile, 'r') as file:
                data = json.load(file)
        return data

    def _write_keyfile(self):
        with open(self.keyfile, 'w') as f:
            json.dump(self.keys, f, ensure_ascii=False, cls=EnhancedJSONEncoder)

    def _gen_table(self, keys, headers=["id", "revoked", "comment", "key"]):
        table = []
        for key in keys:
            row = [key.id, key.revoked, key.comment, key.key]
            table.append(row)
        return tabulate(table, headers, tablefmt="grid")

    def reload_keys(self):
        keys_json = self._read_keyfile()
        for key in keys_json:
            if not self.keys.contains('key', key['key']):
                self.keys.append(Key(**key), 'id')

    def key_revoked(self, id=None, key=None):
        if not id and not key:
            raise KeyManagerException(
                'When revoke a key you must set either `id` or `key`')
        if id and key:
            raise KeyManagerException(
                "When revoke a key `id` and `key` can't be set at the same time")
        action_name = 'id' if id else 'key'
        action_data = id if id else key
        if self.keys.contains(action_name, action_data):
            if not self.keys.get(action_name, action_data).revoked:
                return True
        return False

    def genkey(self, comment=""):
        key = secrets.token_urlsafe(16)
        if not self.keys.contains('key', key):
            index = str(1)
            if len(self.keys):
                index = str(int(self.keys[-1].id) + 1)
            self.keys.append(Key(index, key, comment, False), 'key')
            self._save_key()
            print(self._gen_table(self.keys))
        else:
            print("Key already exist")

    def revokekey(self, id=None, key=None):
        if not id and not key:
            raise KeyManagerException(
                'When revoke a key you must set either `id` or `key`')
        if id and key:
            raise KeyManagerException(
                "When revoke a key `id` and `key` can't be set at the same time")
        action_name = 'id' if id else 'key'
        action_data = id if id else key
        if self.keys.contains(action_name, action_data):
            self._revoke_key(action_name, action_data)
            print(self._gen_table(self.keys))
        else:
            print("Key not found")

    def listkeys(self):
        print(self._gen_table(self.keys))


class keyManagerAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) < 1:
            return
        action = values[0]
        args = {}
        if len(values) > 1:
            for id in range(1, len(values)):
                value = values[id]
                if not re.fullmatch(r'[a-z]+=[a-zA-Z0-9]+', value):
                    raise KeyManagerActionException("The format should be <field>=<data>")
                args_key = value.split('=')[0]
                args_value = value.split('=')[1]
                args[args_key] = args_value
        if type(action) == str:
            method_list = [func for func in dir(KeyManager) if callable(getattr(KeyManager, func))]
            if action in method_list:
                try:
                    getattr(KeyManager(), action)(**args)
                except KeyManagerException as exc:
                    print(f'{action}: {exc}')
                    print(parser.print_help())
                    sys.exit(1)
            else:
                raise KeyManagerException
        sys.exit()

def main():
    parser = argparse.ArgumentParser(description='Simple key management. Generate tokens for any usage.')
    parser.add_argument(
        'genkey', nargs='*', action=keyManagerAction,
        help='Generate a new key. Optional argument comment in the format comment=<comment>')
    parser.add_argument(
        'revokekey', nargs='*', type=int, action=keyManagerAction,
        help='Revoke a key. The format should be <key>=<value> where <key> cant be the id or the key directly')
    parser.add_argument(
        'listkeys', nargs='*', action=keyManagerAction,
        help='List all the key available')
    try:
        args = parser.parse_args()
        print(parser.print_help())
    except Exception as e:
        if e.__class__.__name__ not in  ['KeyManagerException', 'KeyManagerActionException']:
            raise e
        print(parser.print_help())

if __name__ == '__main__':
    main()
