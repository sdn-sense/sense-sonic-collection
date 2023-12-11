#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
import sys
import copy

from ansible_collections.ansible.netcommon.plugins.action.network import ActionModule as ActionNetworkModule
from ansible_collections.sense.sonic.plugins.module_utils.runwrapper import classwrapper

@classwrapper
class ActionModule(ActionNetworkModule):
    """ Ansible Action Module"""

    def run(self, tmp=None, task_vars=None):
        """SONiC Ansible Run"""

        self._config_module = self._task.action.split('.')[-1] == 'sonic_config'

        result = super(ActionModule, self).run(task_vars=task_vars)
        return result
