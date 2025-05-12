import re
import datetime
from distutils.version import LooseVersion
import os
import random
import tempfile
from ansible import errors

def compare_versions(v1, v2):
    try:
        return (LooseVersion(str(v1)) > LooseVersion(str(v2))) - (LooseVersion(str(v1)) < LooseVersion(str(v2)))
    except Exception as e:
        raise errors.AnsibleFilterError(f"Version comparison error between '{v1}' and '{v2}': {str(e)}")

def parse_metrics_file(metrics_path, check_type):
    items = []
    if not os.path.exists(metrics_path):
        raise errors.AnsibleFilterError(f"Metrics file does not exist at: {metrics_path}")

    try:
        with open(metrics_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith('#'):
                    continue

                # Handle software and update metrics differently
                if check_type == 'software' and 'windows_software_info{' not in line:
                    continue
                if check_type == 'updates' and 'windows_update_history{' not in line:
                    continue

                labels_match = re.search(r'\{(.*?)\}', line)
                if not labels_match:
                    continue

                item = {}
                for pair in labels_match.group(1).split(','):
                    key_val = pair.split('=', 1)  # Split on first = only
                    if len(key_val) == 2:
                        key = key_val[0].strip()
                        val = key_val[1].strip().strip('"')
                        item[key] = val

                if check_type == 'software':
                    if 'displayname' in item and 'version' in item:
                        items.append({
                            'name': item['displayname'],
                            'version': item['version']
                        })
                elif check_type == 'updates':
                    if 'title' in item and 'operation' in item and 'status' in item:
                        items.append({
                            'title': item['title'],
                            'operation': item['operation'],
                            'status': item['status'],
                            'kb': item.get('kb', 'none')
                        })

        return items

    except Exception as e:
        raise errors.AnsibleFilterError(f"Error parsing metrics file: {str(e)}")

def check_compliance(value, metrics_content=None, metrics_path=None, check_type='software', **kwargs):
        # Handle case where value is None
    if value is None:
        value = []

    # Ensure value is always a list
    if not isinstance(value, list):
        if isinstance(value, dict):
            # If it's a dict, try to get the appropriate list
            value = value.get('required_software' if check_type == 'software' else 'required_updates', [])
        else:
            value = []
    #print(f"DEBUG: Received value: {value}")
    #print(f"DEBUG: metrics_content: {metrics_content}")
    #print(f"DEBUG: metrics_path: {metrics_path}")
    #print(f"DEBUG: check_type: {check_type}")
    try:
        # value comes from the piped input (required_software or required_updates)
        required_items = value
        # Handle input
        if metrics_content:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_file.write(metrics_content)
                temp_path = temp_file.name
            items_list = parse_metrics_file(temp_path, check_type)
            os.unlink(temp_path)
        elif metrics_path:
            items_list = parse_metrics_file(metrics_path, check_type)
        else:
            items_list = []

        results = []
        counts = {'compliant': 0, 'non_compliant': 0, 'missing': 0}
        if check_type == 'software':
            counts['name_match'] = 0

        for req in required_items:
            if not isinstance(req, dict):
                continue

            if check_type == 'software':
                req_name = req.get('name', '')
                req_version = req.get('version', '0')
                installed_version = 'missing'
                is_compliant = False
                match_found = False
                name_match_only = False

                for item in items_list:
                    if req_name == item.get('name', ''):
                        installed_version = item.get('version', 'unknown')
                        match_found = True
                        break

                if match_found:
                    if req_version.lower() == 'unknown' or installed_version.lower() == 'unknown':
                        name_match_only = True
                        counts['name_match'] += 1
                    else:
                        is_compliant = compare_versions(installed_version, req_version) == 0
                        if is_compliant:
                            counts['compliant'] += 1
                        else:
                            counts['non_compliant'] += 1
                else:
                    counts['missing'] += 1

                results.append({
                    'name': req_name,
                    'required_version': req_version,
                    'installed_version': installed_version,
                    'compliant': is_compliant,
                    'found': match_found,
                    'name_match': name_match_only
                })

            elif check_type == 'updates':
                # Skip if required fields are missing
                if not all(k in req for k in ['title', 'operation', 'status']):
                    continue

                req_title = req.get('title', '')
                req_operation = req.get('operation', '').lower()
                req_status = req.get('status', '').lower()

                found = False
                is_compliant = False
                found_item = {}

                for item in items_list:
                    # Skip if installed item is missing required fields
                    if not all(k in item for k in ['title', 'operation', 'status']):
                        continue

                    item_title = item.get('title', '')
                    # Flexible title matching - check if required is contained in installed
                    if req_title.lower() in item_title.lower():
                        found = True
                        found_item = item
                        item_operation = item.get('operation', '').lower()
                        item_status = item.get('status', '').lower()
                        if (req_operation == item_operation and
                            req_status == item_status):
                            is_compliant = True
                        break

                if found:
                    if is_compliant:
                        counts['compliant'] += 1
                    else:
                        counts['non_compliant'] += 1
                else:
                    counts['missing'] += 1

                results.append({
                    'title': req_title,
                    'required_operation': req_operation,
                    'required_status': req_status,
                    'found_operation': found_item.get('operation', '') if found else 'missing',
                    'found_status': found_item.get('status', '') if found else 'missing',
                    'unique_number': random.randint(1000000000, 9999999999),
                    'compliant': is_compliant,
                    'found': found
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
            'check_compliance': check_compliance
        }