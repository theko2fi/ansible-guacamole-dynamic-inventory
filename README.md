# guacamole_inventory – Ansible dynamic inventory plugin for Apache Guacamole

Wait would you say about getting all your connections details from Apache Guacamole and parsing them to ansible as inventory ? It would be amazing, right ? 

Guess what, You are in the right place. It's all about this plugin.

> **Note**
>
> In Apache Guacamole world, **connection** is the word used for a server. In Ansible world, it's **host**. So all over this documentation, **connection** and **host** mean the same thing.
>

## Synopsis

- Get connection details from Apache Guacamole API and parse them to ansible as inventory.
- Uses an YAML inventory file ending with either `guacamole.yml` or `guacamole.yaml` to set parameter values.

## Requirements

The below requirements are needed on the local controller node that executes this inventory.

- python >= 2.7
- The host that executes this module must have ansible installed

## Installation

> This inventory plugin is a standalone plugin (outside of a collection).

To install the plugin, copy the `guacamole_inventory.py` file contained in this repository, to the `DEFAULT_INVENTORY_PLUGIN_PATH` on your machine. `DEFAULT_INVENTORY_PLUGIN_PATH` is a colon separated paths list in which Ansible will search for Inventory Plugins by default.

Execute `ansible-config dump | grep DEFAULT_INVENTORY_PLUGIN_PATH` to view your current configuration settings for Inventory Plugins. After the plugin file is added to one of these locations, Ansible loads it and you can use it in any local module, task, playbook, or role.

If the plugin has been successfully installed, the execution of `ansible-doc -t inventory guacamole_inventory` should display the present documentation.

## Parameters
```yaml
    plugin:
        description: Token that ensures this is a source file for the 'guacamole_inventory' plugin.
        type: string
        required: true
        choices: [ guacamole_inventory ]
    base_url:
        description:
          - URL of the Apache Guacamole instance.
          - It is recommended to use HTTPS so that the username/password are not
            transferred over the network unencrypted.
        required: true
        type: string
    auth_username:
        description: the username to authenticate against the Apache Guacamole API
        type: string
        default: guacadmin
        env:
          - name: GUACAMOLE_USER
    auth_password:
        description: the password to authenticate against the Apache Guacamole API
        type: string
        default: guacadmin
        env:
          - name: GUACAMOLE_PASSWORD
    selected_connection_groups:
        description:
          - A list of connection group names to search for connections.
          - 'ROOT' will include all connections from Guacamole instance.
        type: list
        elements: str
        default: ["ROOT"]
    validate_certs:
        description:
            - Validate ssl certs?
        default: true
        type: bool
```

## Usage

To use it in a playbook, create an inventory file ending with either `guacamole.yml` or `guacamole.yaml` and specify: `guacamole_inventory` as plugin. Take a look at the sample below.

## Examples

```yaml
# sample 'myhosts.guacamole.yaml'

# required for all guacamole_inventory inventory plugin configs
plugin: guacamole_inventory

# the URL to your Guacamole instance 
base_url: http://localhost:8080/guacamole

# the username to authenticate against the Apache Guacamole API
auth_username: guacadmin

# the password to authenticate against the Apache Guacamole API
auth_password: guacadmin

# places a host in the named group if the associated condition evaluates to true
groups:
  # since this will be true for every host, every host sourced from this inventory plugin config will be in the
  # group 'all_the_hosts'
  all_the_hosts: true
  # if the connection's "name" variable contains "webserver", it will be placed in the 'web_hosts' group
  web_hosts: "'webserver' in name"

# adds variables to each host found by this inventory plugin, whose values are the result of the associated expression
compose:
  my_host_var:
  # A statically-valued expression has to be both single and double-quoted, or use escaped quotes, since the outer
  # layer of quotes will be consumed by YAML. Without the second set of quotes, it interprets 'staticvalue' as a
  # variable instead of a string literal.
  some_statically_valued_var: "'staticvalue'"
  # In this case, the variable we_come_from_guacamole with value 'yes' will be added to all host listed by this plugin.
  we_come_from_guacamole: "'yes'"
  # overrides the default ansible_ssh_private_key_file value with a custom path.
  ansible_ssh_private_key_file: /path/to/my/secondkey/id_rsa
 
# places hosts in dynamically-created groups based on a variable value.
keyed_groups:
# places each connection which uses the same username in a group named 'username_(username value)'
- prefix: username
  key: username
# places each host in a group named 'ssh_port_(port number)', depending on the connection port number
- prefix: ssh_port
  key: port

# fetches connections from an explicit list of connection groups instead of default all (- 'ROOT')
selected_connection_groups:
- databases_servers
- apache_servers
```

## Execution

Let's say you have a directory containing your inventory file `myhosts.guacamole.yml` and the `playbook.yml` you would like to play on the hosts listed by the plugin, then the command would be:

`ansible-playbook -i myhosts.guacamole.yml playbook.yml`

If you just want to see the hosts listed by the plugin :

- `ansible-inventory -i myhosts.guacamole.yml --list`
- `ansible-inventory -i myhosts.guacamole.yml --list --yaml`
- `ansible-inventory -i myhosts.guacamole.yml --graph`


> **Warning**:
> This plugin handles ssh connections only.
> VNC and RDP hosts won't be listed by this plugin.
> Ansible and ssh protocol don't support ssh key as string variable.
> For hosts using private-key, they will use `~/.ssh/id_rsa` as default key file.
