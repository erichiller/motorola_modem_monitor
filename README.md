# Motorola Modem Monitor

Track stats from Motorola cable modem (test with MB8600)

## Build

```bat
docker image build . -t ehiller/motorola-modem-monitor:latest -t ehiller/motorola-modem-monitor:ws2019sc
```

## Run

```bat
docker run --name motorola-modem-monitor --env-file ./config/.env ehiller/motorola-modem-monitor:latest
```

### Run detached

```bat
docker image build . -t ehiller/motorola-modem-monitor:latest -t ehiller/motorola-modem-monitor:ws2019sc
docker container rm -f motorola-modem-monitor
docker run --name motorola-modem-monitor -d --env-file ./config/.env ehiller/motorola-modem-monitor:latest
```

## Example `.env` file

```dotenv
ELASTICSEARCH_HOST=host.domain.tld:9200
ELASTICSEARCH_INDX=mb8600_modem
INFLUXDB_HOST=host.domain.tld
INFLUXDB_DATABASE=mb8600_modem
```

## References

- <https://github.com/bikerp/dsp-w215-hnap/wiki/Authentication-process>