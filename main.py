import pefile
import os
import shutil
import re
import argparse
import glob
from collections import defaultdict

def get_dependencies(file_path):
    try:
        pe = pefile.PE(file_path)
        dlls = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dlls.append(entry.dll.decode('utf-8'))
        else:
            print(f"No import table found in {file_path}.")
        return dlls
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return []

def search_and_copy_dlls(dll_map, search_dirs, output_dir, build_type, log_file, collected_files=None, exclude_dirs=None):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if collected_files is None:
        collected_files = set()

    if exclude_dirs is None:
        exclude_dirs = []

    exclude_dirs = [os.path.normpath(dir) for dir in exclude_dirs]
    
    new_files = set()

    with open(log_file, 'a') as log:
        log.write(f"Starting DLL search and copy process for build type: {build_type}\n\n")

        for search_dir in search_dirs:
            for root, dirs, files in os.walk(search_dir):
                # Skip excluded directories
                root_drive = os.path.splitdrive(root)[0]
                if any(
                    root_drive == os.path.splitdrive(exclude)[0] and
                    os.path.commonpath([root, exclude]) == exclude
                    for exclude in exclude_dirs
                ):
                    continue

                for file in files:
                    if file in dll_map:
                        full_file_path = os.path.join(root, file)
                        full_file_path = '/'.join(full_file_path.split(os.path.sep))

                        should_copy = False

                        # Check if the path contains the build type if it is specified
                        if build_type in full_file_path:
                            should_copy = True
                        elif "/debug/" not in full_file_path and "/release/" not in full_file_path:
                            should_copy = True

                        if should_copy:
                            if file in collected_files:
                                log.write(f"Skipping already copied file: {full_file_path}\n")
                            else:
                                destination_path = os.path.join(output_dir, file)
                                try:
                                    shutil.copy(full_file_path, destination_path)
                                    new_files.add(file)
                                    sources = ', '.join(dll_map[file])
                                    log.write(f"Copied: {full_file_path} to {destination_path} (Dependency of: {sources})\n")
                                    print(f"Copied: {full_file_path} to {destination_path} (Dependency of: {sources})")
                                except OSError as e:
                                    log.write(f"Failed to copy {full_file_path} to {destination_path}: {e}\n")
                                    print(f"Failed to copy {full_file_path} to {destination_path}: {e}")

    collected_files.update(new_files)
    return new_files

def find_dlls(directory):
    dlls = []
    pattern = re.compile(r"^Ds.*\\.dll$", re.IGNORECASE)
    for root, dirs, files in os.walk(directory):
        for file in files:
            if pattern.match(file):
                dlls.append(os.path.join(root, file))
    return dlls

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect DLL dependencies for specified executables and DLLs.")
    parser.add_argument("--exe_files", nargs='+', required=True, help="Paths to the exe files. Supports wildcards.")
    parser.add_argument("--search_dirs", nargs='+', required=True, help="Directories to search for dependencies.")
    parser.add_argument("--output_dir", default="./output", help="Directory to copy the found DLLs to.")
    parser.add_argument("--build_type", required=True, choices=["debug", "release"], help="Build type to consider in paths.")
    parser.add_argument("--log_file", default="./log.txt", help="Path to the log file.")
    parser.add_argument("--exclude_dirs", nargs='*', default=[], help="Directories to exclude from the search.")
    parser.add_argument("--recursive", action='store_true', help="Flag to enable recursive dependency search. Default is disabled.")

    args = parser.parse_args()

    exe_files = []
    for pattern in args.exe_files:
        exe_files.extend(glob.glob(pattern))

    exe_files = [os.path.normpath(file) for file in exe_files]
    search_dirs = [os.path.normpath(dir) for dir in args.search_dirs]
    output_dir = os.path.normpath(args.output_dir)
    build_type = args.build_type
    log_file = os.path.normpath(args.log_file)
    exclude_dirs = [os.path.normpath(dir) for dir in args.exclude_dirs]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    dll_map = defaultdict(list)  # Map of DLLs to their sources

    for exe_path in exe_files:
        dependencies = get_dependencies(exe_path)
        for dll in dependencies:
            dll_map[dll].append(exe_path)

    # Assume this_directory is the same as the directory containing the first exe file
    if exe_files:
        this_directory = os.path.dirname(exe_files[0])
        dlls = find_dlls(this_directory)
        for dll_path in dlls:
            dependencies = get_dependencies(dll_path)
            for dll in dependencies:
                dll_map[dll].append(dll_path)

    dll_list = list(dll_map.keys())  # Remove duplicates
    collected_files = search_and_copy_dlls(dll_map, search_dirs, output_dir, build_type, log_file, exclude_dirs=exclude_dirs)

    # Recursively check dependencies for copied DLLs if the recursive flag is set
    if args.recursive:
        while collected_files:
            new_dependencies = defaultdict(list)
            for copied_file in collected_files:
                copied_file_path = os.path.join(output_dir, copied_file)
                dependencies = get_dependencies(copied_file_path)
                for dll in dependencies:
                    new_dependencies[dll].append(copied_file_path)

            dll_map.update(new_dependencies)
            collected_files = search_and_copy_dlls(new_dependencies, search_dirs, output_dir, build_type, log_file, collected_files, exclude_dirs=exclude_dirs)
