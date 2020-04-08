
# Constellix Dynamic DNS Client.

A Python 3.5 based Dynamic DNS written for version 1 of the Constellix Managed DNS API.

https://constellix.com/

## Getting Started

To get started quickly;

 1. Install the client
 2. Create records in Constellix
 3. Create a client configuration file
 4. Run the client
 5. Automatically run the client


### Install the client

Install the client using the following steps.

```$shell
git clone <url>
cd constellix-dynamicdns-client
sudo pip install .
```

Using `sudo` to run `pip install` will make `ddns-client` available system wide to all users.

If you don't wish to use `sudio` then `ddns-client` will be installed in `~/.local/bin/`. You should add this to your `$PATH` if it's not already there.

To use without installing via pip you can load the client as a module while your are in the source directory.

```$shell
cd constellix-dynamicdns-client
python -m ddns_client --help
```

Note that python 3.5 or later is required. If you see errors such as `SyntaxError: invalid syntax` you should check which version of python you are using.

```$shell
python --version
```


### Create records in Constellix

Before using this client it is recommended that you setup records within Constellix DNS.

It is recommend to create both an `A` record and a `AAAA`, but only one or the other is necessary.

### Create a configuration file

Default location for the configuration file is `~/.ddns/constellix.json`

The configuration file acts as defaults for the command line arguments, so any available argument is something that can be configured.

Example minimal configuration:
```$json
{
    "key": "<API-KEY>",
    "secret": "<SECRET-KEY>",
    "name": "host.example.com"
}
```

### Run the client

View the usage and help information.

```$shell
ddns-client --help
ddns-client myip --help
ddns-client ddns --help
```

View your external IP addresses.

```$shell
# output human readable table showing external IP addresses
ddns-client myip query

# output machine readable json with external IP addresses
ddns-client myip query -p constellix -f json
```

View the current value of the DNS records.

This is also a useful way to verify that your API credentials are working correctly.

```$shell
ddns-client ddns query
```

Update the the DNS records.

This will automatically determine your external IP address then use the API to update the DNS records at Constellix. 

```$shell
# fully automatic mode (with configuration file)
ddns-client

# manually specifying name and ip address
ddns-client ddns update --name host.example1.com --ip ::1
```

### Automatically run the client

You should ensure that this command is run every time that your IP address changes. Either through your network configuration, or simply by running it via cron.

Example of running the client when the network changes
```
# /etc/network/interfaces
auto eth0
    iface eth0 inet dhcp
    up ddns-client
```

Example of running the client via cron
```
# /etc/crontab
*/1 * * * * root ddns-client
```

### Improving performance

For convenience you may specify the hostname which is to be updated. However it is more preformat to specify the domain ID and the record IDs, because this avoids the API calls needed to look them up.

Note that it is also permissible to specify only the domain ID, which is useful if you wish to script updates a wide variety of records. However specifying both record IDs and a name will result in the name being ignored.

The IDs are specified in the following way
```$shell
ddns-client ddns query --id DOMAIN_ID [RECORD_ID [RECORD_ID ...]]

# example
ddns-client ddns query --id 123456 A:123456

# advanced example
ddns-client ddns query -4 --id 123456 --name myipv4name
ddns-client ddns query -6 --id 123456 --name myipv6name 
```

You can find the ID numbers using the `ddns query` sub command with  a hostname argument.

```$shell
ddns-client ddns query --name host.example.com
```
