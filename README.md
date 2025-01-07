# digging

A Python-based tool for identifying and collecting DLL dependencies efficiently, with support for recursive dependency resolution and build-type differentiation.

## Features
- Automatically detects and extracts DLL dependencies from specified `.exe` files.
- Searches for DLL files in specified directories.
- Supports recursive dependency resolution for copied DLLs.
- Differentiates between `debug` and `release` build types.
- Logs all operations to a specified log file.

## Requirements
- Python 3.6 or later
- `pefile` library (install using `pip install pefile`)

## Usage

### Help Command
To display the help message with all available options:
```bash
python main.py --help
```

### Example Usage

#### Debug Build
```bash
python main.py \
  --exe_files your_app.exe \
  --search_dirs C:/Qt/Qt5/bin E:/Libs \
  --output_dir ./output \
  --build_type debug \
  --log_file ./log.txt
```

#### Release Build
```bash
python main.py \
  --exe_files your_app.exe \
  --search_dirs C:/Qt/Qt5/bin E:/Libs \
  --output_dir ./output \
  --build_type release \
  --log_file ./log.txt
```

## Script Arguments
- `--exe_files`: Paths to the executable (`.exe`) files to analyze. Multiple paths can be specified, separated by spaces.
- `--search_dirs`: Directories to search for the DLL dependencies. Multiple directories can be specified, separated by spaces.
- `--output_dir`: Directory where the found DLLs will be copied. Defaults to `./output`.
- `--build_type`: Specifies the build type. Accepted values are `debug` or `release`.
	- For debug builds, the file path must contain /debug/.
- `--log_file`: Path to the log file where the process details will be recorded. Defaults to `./log.txt`.

## Logging
All operations, including skipped and copied files, are logged to the specified log file. This ensures traceability and helps diagnose any issues during execution.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

