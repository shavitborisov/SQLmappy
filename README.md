# SQLmappy
Lightweight SQLmap-like tool for MySQL servers.
Full documentation can be found [here](https://docs.google.com/document/d/1hJoeEGa1F9oaqeVJfRvHYCs2-8y_BL9iQ9vrGZQIWDo/edit?usp=sharing).

## Usage
```commandline
usage: SQLmappy [-h] -u URL [-v] [-l] [-m] [-p EXPORT_CSV] (-e | -b)

Lightweight SQLmap-like tool

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to pen-test on
  -v, --verbose         Verbose flag
  -l, --login-dvwa      login to DVWA server
  -m, --manual          Execute manual queries
  -p EXPORT_CSV, --export-csv EXPORT_CSV
                        Save the data into a file
  -e, --error-based     Perform error-based SQL injection
  -b, --boolean-based   Perform boolean-based SQL injection

Happy pen-testing!
```

## Demo
### Error-based attack (automatic detection and exploitation)
[![asciicast](https://asciinema.org/a/fkuOK4lHJC0h6OAhMa3hzy8G6.svg)](https://asciinema.org/a/fkuOK4lHJC0h6OAhMa3hzy8G6)

### Boolean-based attack (automatic detection and exploitation)
[![asciicast](https://asciinema.org/a/566614.svg)](https://asciinema.org/a/566614)

### Manual query mode over error-based attack
[![asciicast](https://asciinema.org/a/566616.svg)](https://asciinema.org/a/566616)
