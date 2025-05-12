import re
import datetime
import os
import random
import tempfile
from ansible import errors

def compare_versions(v1, v2):
    """Simple string equality check"""
    try:
        return str(v1).strip() == str(v2).strip()
    except Exception as e:
        raise errors.AnsibleFilterError(f"String comparison error between '{v1}' and '{v2}': {str(e)}")

def parse_metrics_file(metrics_path, check_type):
    items = []
    if not os.path.exists(metrics_path):
        raise errors.AnsibleFilterError(f"Metrics file does not exist at: {metrics_path}")

    try:
        with open(metrics_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith('#'):
                    continue

                if check_type == 'software' and 'linux_software_info{' not in line:
                    continue

                labels_match = re.search(r'\{(.*?)\}', line)
                if not labels_match:
                    continue

                item = {}
                for pair in labels_match.group(1).split(','):
                    key_val = pair.split('=', 1)
                    if len(key_val) == 2:
                        key = key_val[0].strip()
                        val = key_val[1].strip().strip('"')
                        item[key] = val

                if check_type == 'software':
                    if 'name' in item and 'version' in item:
                        # Add hashname to each item by combining name and version
                        item['hashname'] = f"{item['name']}-{item['version']}"
                        items.append(item)

        return items

    except Exception as e:
        raise errors.AnsibleFilterError(f"Error parsing metrics file: {str(e)}")

def linux_check_compliance(value, metrics_content=None, metrics_path=None, check_type='software', **kwargs):
    if value is None:
        value = []

    if not isinstance(value, list):
        if isinstance(value, dict):
            value = value.get('required_software' if check_type == 'software' else 'required_updates', [])
        else:
            value = []

    try:
        required_items = value
        if metrics_content:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_file.write(metrics_content)
                temp_path = temp_file.name
            installed_items = parse_metrics_file(temp_path, check_type)
            os.unlink(temp_path)
        elif metrics_path:
            installed_items = parse_metrics_file(metrics_path, check_type)
        else:
            installed_items = []

        results = []
        counts = {'compliant': 0, 'non_compliant': 0, 'missing': 0}

        # Create lookup dictionary by hashname
        installed_by_hash = {item['hashname']: item for item in installed_items}
        # Create lookup dictionary by name for fallback checking
        installed_by_name = {}
        for item in installed_items:
            if item['name'] not in installed_by_name:
                installed_by_name[item['name']] = []
            installed_by_name[item['name']].append(item['version'])

        for req in required_items:
            if not isinstance(req, dict):
                continue

            if check_type == 'software':
                req_hashname = req.get('hashname')
                req_name = req.get('name', '')
                req_version = req.get('version', '0')

                # Find matching installed package by hashname
                installed_pkg = installed_by_hash.get(req_hashname)
                is_compliant = installed_pkg is not None
                match_found = is_compliant
                installed_version = "Unknown"

                if match_found:
                    counts['compliant'] += 1
                    installed_version = installed_pkg['version']
                else:
                    # Check if at least the name exists (even if version doesn't match)
                    if req_name in installed_by_name:
                        installed_version = ", ".join(installed_by_name[req_name])
                        counts['non_compliant'] += 1
                    else:
                        counts['missing'] += 1

                results.append({
                    'hashname': req_hashname,
                    'name': req_name,
                    'required_version': req_version,
                    'installed_version': installed_version,
                    'compliant': is_compliant,
                    'found': match_found,
                    'unique_number': random.randint(1000000000, 9999999999)
                })

        return {
            'results': results,
            'counts': counts,
            'timestamp': datetime.datetime.now().isoformat()
        }

    except Exception as e:
        raise errors.AnsibleFilterError(f"Compliance check failed: {str(e)}")

class FilterModule(object):
    def filters(self):
        return {
            'linux_check_compliance': linux_check_compliance
        }