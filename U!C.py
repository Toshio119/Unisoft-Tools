import re
import subprocess
import os

"""
U!C Static Analyzer for C Programs: Catching Segmentation Faults:
The U!C static analyzer is a powerful tool designed specifically for analyzing C programs to 
identify potential segmentation faults before they occur during runtime.
By Toshio Nayashima
"""

# Keywords and patterns that are common causes of segmentation faults
RISK_PATTERNS = {
    'uninitialized_pointer': re.compile(r'(\w+\s*\*\s*\w+\s*;)', re.MULTILINE),
    'null_dereference': re.compile(r'(\*\w+)\s*=\s*(NULL|0);', re.MULTILINE),
    'dangling_pointer': re.compile(r'free\s*\((\w+)\);', re.MULTILINE),
    'array_out_of_bounds': re.compile(r'\w+\[\d+\]\s*=\s*\w+', re.MULTILINE),
    'unsafe_pointer_arithmetic': re.compile(r'\w+\s*=\s*\w+\s*[\+\-]\s*\d+', re.MULTILINE),
    'malloc': re.compile(r'\bmalloc\s*\(', re.MULTILINE),
    'calloc': re.compile(r'\bcalloc\s*\(', re.MULTILINE),
    'realloc': re.compile(r'\brealloc\s*\(', re.MULTILINE),
    'free': re.compile(r'\bfree\s*\(', re.MULTILINE)
}

def check_syntax(file_path):
    """
    Check for syntax errors in the given C file using GCC.
    
    :param file_path: Path to the C file
    :return: True if no syntax errors, False if errors are found
    """
    # Run GCC with -fsyntax-only, -Wall, -Wextra option and specify output file as a.out
    print("U!C::Gcc Syntax analysis: ")
    result = subprocess.run(['gcc', '-fsyntax-only', '-Wall', '-Wextra', file_path, '-o', 'a.out'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Check for syntax errors
    if result.returncode != 0:
        print(f"U!C::Syntax errors detected in {file_path}:\n{result.stderr}")
        return False

    # Delete the output execution file a.out if it exists
    if os.path.exists('a.out'):
        os.remove('a.out')
        print("U!C::Removed output file a.out.")

    return True

def analyze_c_file(file_path):
    """
    Analyze the given C file and print potential risks for segmentation faults, 
    including line numbers and memory allocation/deallocation counts.
    
    :param file_path: Path to the C file
    """
    # Check for syntax errors first
    if not check_syntax(file_path):
        print("U!C::Terminating analysis due to syntax errors.")
        return
    else:
        print("U!C::No Syntax error's found")
    with open(file_path, 'r') as file:
        code_lines = file.readlines()

    print(f"U!C::Analyzing {file_path} for potential segmentation fault risks...\n")

    # Counters for allocation and deallocation
    malloc_count = 0
    calloc_count = 0
    realloc_count = 0
    free_count = 0

    # Set to track freed pointers
    freed_pointers = set()

    # Analyzing each line for potential risks
    for line_number, line in enumerate(code_lines, start=1):
        # Check for uninitialized pointers
        if RISK_PATTERNS['uninitialized_pointer'].search(line):
            print(f"U!C::Line {line_number}: Risk - Uninitialized Pointer detected! -> {line.strip()}")

        # Check for null dereferences
        null_dereferences = RISK_PATTERNS['null_dereference'].findall(line)
        if null_dereferences:
            for match in null_dereferences:
                print(f"U!C::Line {line_number}: Risk - Null dereference detected! Pointer '{match[0]}' assigned to {match[1]}.")

        # Check for dangling pointers (freed but possibly used later)
        dangling_pointers = RISK_PATTERNS['dangling_pointer'].search(line)
        if dangling_pointers:
            pointer_name = dangling_pointers.group(1)
            if pointer_name in freed_pointers:
                print(f"U!C::Line {line_number}: Warning - Double-free detected! Pointer '{pointer_name}' has already been freed.")
            else:
                freed_pointers.add(pointer_name)

        # Check for potential out-of-bounds array accesses
        if RISK_PATTERNS['array_out_of_bounds'].search(line):
            print(f"U!C::Line {line_number}: Risk - Potential out-of-bounds array access detected! -> {line.strip()}")

        # Check for unsafe pointer arithmetic
        if RISK_PATTERNS['unsafe_pointer_arithmetic'].search(line):
            print(f"U!C::Line {line_number}: Risk - Unsafe pointer arithmetic detected! -> {line.strip()}")

        # Count allocations and deallocations
        if RISK_PATTERNS['malloc'].search(line):
            malloc_count += 1
            print(f"U!C::Line {line_number}: Detected malloc allocation -> {line.strip()}")
        
        if RISK_PATTERNS['calloc'].search(line):
            calloc_count += 1
            print(f"U!C::Line {line_number}: Detected calloc allocation -> {line.strip()}")

        if RISK_PATTERNS['realloc'].search(line):
            realloc_count += 1
            print(f"U!C::Line {line_number}: Detected realloc allocation -> {line.strip()}")

        if RISK_PATTERNS['free'].search(line):
            free_count += 1
            print(f"U!C::Line {line_number}: Detected memory deallocation using free -> {line.strip()}")

        # Check if any freed pointer is used again
        for pointer in freed_pointers:
            if re.search(rf'\b{pointer}\b', line):
                print(f"U!C::Line {line_number}: Warning - Use-after-free detected! Pointer '{pointer}' used after being freed.")

    # Buffer overflow risk detection
    buffer_overflow_risk = re.compile(r'\b(strcpy|strcat|gets|sprintf)\b')
    for line_number, line in enumerate(code_lines, start=1):
        if buffer_overflow_risk.search(line):
            print(f"U!C::Line {line_number}: Warning - Buffer overflow risk detected! Consider using safer alternatives (e.g., strncpy, strncat).")

    # Function definition detection
    function_patterns = re.compile(r'\b(\w+)\s+\*?\s*(\w+)\s*\(.*\)\s*{')
    for line_number, line in enumerate(code_lines, start=1):
        if function_patterns.search(line):
            print(f"U!C::Line {line_number}: Function '{function_patterns.search(line).group(2)}' definition detected.")

    # Realloc usage check
    realloc_usage = re.compile(r'\b(\w+)\s*=\s*realloc\s*\(([^)]+)\)')
    for line_number, line in enumerate(code_lines, start=1):
        if realloc_usage.search(line):
            pointer, args = realloc_usage.search(line).groups()
            if pointer not in args:
                print(f"U!C::Line {line_number}: Warning - Potential realloc issue! Ensure proper handling if realloc fails.")


    # Check for potential memory leaks or mismatched allocations/deallocations
    total_allocations = malloc_count + calloc_count + realloc_count
    if total_allocations > free_count:
        print(f"\nU!C::Warning: Potential memory leak detected! There are more allocations ({total_allocations}) than deallocations ({free_count}).")
    elif total_allocations < free_count:
        print(f"\nU!C::Warning: More deallocations ({free_count}) than allocations ({total_allocations}). This might indicate a double-free error or inappropriate use of free.")
    else:
        print("\nU!C::Memory management looks balanced (equal allocations and deallocations).")

    print("\nU!C::Analysis complete.")

if __name__ == "__main__":
   
    c_file_path = "lol.c"
    analyze_c_file(c_file_path)
