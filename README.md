# router-signal-logging
Get signal info from LTE router and stuff it into a csv file.

Based on https://github.com/mkorz/b618reboot

# Config

Set router ip, username, password and log filename in `config.py`

Set cron to run the script every 5 minutes:

`*/5 * * * * cd ~/signal_logging && python3 signal_logger.py`
