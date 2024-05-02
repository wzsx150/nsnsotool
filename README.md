# nsnsotool
Compress or decompress NSO files for Nintendo Switch.  
Python version, ported from https://github.com/0CBH0/nsnsotool

## Dependencies
lz4

## Usage
```
nsnsotool.py [-h] (-c | -d) input_file [output_file]

positional arguments:
  input_file        Input file path
  output_file       Output file path (optional, if not provided, overwrite the input file)

optional arguments:
  -h, --help        show this help message and exit
  -c, --compress    Compress NSO/NRO file
  -d, --decompress  Decompress NSO/NRO files
```

## Credits
[nsnsotool](https://github.com/0CBH0/nsnsotool)