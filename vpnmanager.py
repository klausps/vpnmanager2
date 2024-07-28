import yaml
import argparse
from yamlcontrollers import process_operations


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process YAML operations.')
    parser.add_argument('file_path', type=str, help='Path to the YAML file containing operations')
    args = parser.parse_args()

    process_operations(args.file_path)