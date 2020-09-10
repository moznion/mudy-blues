# mudy-bluez (mbz)

HTTP request re-player and the response verifier, based on packet capturing.

## Usage

### Get packet capture

example:

```
$ tcpdump -i any -w test.pcapng port 12345 and tcp
```

### run `mbz`

```
$ mbz test.pcapng
```

## Author

moznion (<moznion@gmail.com>)
