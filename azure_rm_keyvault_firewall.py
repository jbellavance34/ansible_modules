#!/usr/bin/python
#
# Copyright (c) 2017 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# subnet '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/subnet1'.
# keyvault /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sample-resource-group/providers/Microsoft.KeyVault/vaults/sample-vault

#        def backend_address_pool_id(subscription_id, resource_group_name, load_balancer_name, name):
#            """Generate the id for a backend address pool"""
#            return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/loadBalancers/{2}/backendAddressPools/{3}'.format(
#                subscription_id,
#                resource_group_name,
#                load_balancer_name,
#                name
#            )

DOCUMENTATION = '''
---
module: azure_rm_keyvault_firewall
short_description: Manage azure keyvault firewall
'''

EXAMPLES = '''
- name: Add a subnet to keyvault firewall
  azure_rm_keyvault_firewall:
    azure_auth: "{{ Authorization: Bearer <bearer-token> }}"
    keyvault_id: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}'
    subnet_id: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}'
    state: present
  register: result

- name: Remove a subnet to keyvault firewall
  azure_rm_keyvault_firewall:
    azure_auth: "{{ Authorization: Bearer <bearer-token> }}"
    keyvault_id: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}'
    subnet_id: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}'
    state: absent
  register: result
'''

from ansible.module_utils.basic import *
import requests

api_url = "management.azure.com"
keyvault_api_version = '?api-version=2018-02-14'

def kv_fw_rule_present(data):

    api_key = data['azure_auth']
    keyvault_id = data['keyvault_id']
    subnet_id = data['subnet_id']

    body_data = {
                "properties": {
                    "vaultUri": keyvault_id
                    },
                    "networkAcls": {
                        "virtualNetworkRules": [
                            subnet_id
                            ]
                    }
                }


    headers = {
        "{}" . format(api_key)
    }

    url = "{}{}{}" . format(api_url, keyvault_id, keyvault_api_version)
    result = requests.patch(url, json.dumps(data), headers=headers)

    if result.status_code == 200:
        return False, True, result.json()

    # default: something went wrong
    meta = {"status": result.status_code, 'response': result.json()}
    return True, False, meta

def kv_fw_rule_absent(data=None):
        # TODO
        result = {"status": 2, "data": "feature absent not implemented yet"}
        return True, False, result


def main():

    fields = {
        "azure_auth": {"required": True, "type": "str"},
        "keyvault_id": {"required": True, "type": "str"},
        "subnet_id": {"required": True, "type": "str"},
        "state": {
            "default": "present",
            "choices": ['present', 'absent'],
            "type": 'str'
        },

    }

    choice_map = {
        "present": kv_fw_rule_present,
        "absent": kv_fw_rule_absent,
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Module azure_rm_keyvault_firewall failed", meta=result)


if __name__ == '__main__':
    main()
