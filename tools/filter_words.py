import sys

# For the username_generator, we sourced a large list of words
# and this script was used to filter the forbidden_words.txt from
# all of the other files in the /username_wordlist directory.
# Has no 3rd party dependencies so you can run it without much else than Python3.



def main():
    use_substring = '--substring' in sys.argv
    if use_substring:
        sys.argv.remove('--substring')

    filter_file = sys.argv[1]
    target_file = sys.argv[2]

    with open(filter_file, 'r', encoding='utf-8') as f:
        filter_words = set(line.strip() for line in f if line.strip())


    with open(target_file, 'r', encoding='utf-8') as f:
        target_lines = [line.strip() for line in f]

    if use_substring:
        filtered_lines = [
            line for line in target_lines
            if line and not any(filter_word in line for filter_word in filter_words)
        ]
    else:
        filtered_lines = [line for line in target_lines if line and line not in filter_words]

    # Count removed words
    original_count = len([line for line in target_lines if line])
    removed_count = original_count - len(filtered_lines)

    try:
        with open(target_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(filtered_lines))
            if filtered_lines:
                f.write('\n')
    except Exception as e:
        print(f"Error writing to target file: {e}")
        sys.exit(1)

    print(f"Count before : {original_count}")
    print(f"Count after  : {len(filtered_lines)}")

if __name__ == '__main__':
    main()
