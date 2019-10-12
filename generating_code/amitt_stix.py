from datetime import datetime
import pandas as pd
import os
import json
import uuid
import xlrd

class Amitt:
    ''' Manage AMITT metadata

    Create MISP galaxy and cluster JSON files from the AMITT metadata xlsx.

    '''

    def __init__(self, infile = 'amitt_metadata_v3.xlsx'):
        
        # Load metadata from file
        metadata = {}
        xlsx = pd.ExcelFile(infile)
        for sheetname in xlsx.sheet_names:
            metadata[sheetname] = xlsx.parse(sheetname)

        # Create individual tables and dictionaries
        self.phases = metadata['phases']
        self.techniques = metadata['techniques']
        self.tasks = metadata['tasks']
        self.incidents = metadata['incidents']

        tactechs = self.techniques.groupby('tactic')['id'].apply(list).reset_index().rename({'id':'techniques'}, axis=1)
        self.tactics = metadata['tactics'].merge(tactechs, left_on='id', right_on='tactic', how='left').fillna('').drop('tactic', axis=1)

        self.phasedict = self.make_object_dict(self.phases)
        self.tacdict   = self.make_object_dict(self.tactics)
        self.techdict  = self.make_object_dict(self.techniques)

        self.stix_bundle = {}
        self.stix_created_by = str(uuid.uuid4())
        self.stix_marking_definition = str(uuid.uuid4())
        self.stix_creation_timestamp = datetime.now().isoformat()

    def make_object_dict(self, df):
        return(pd.Series(df.name.values,index=df.id).to_dict())

    def write_amitt_file(self, fname, file_data):
        with open(fname, 'w') as f:
            json.dump(file_data, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write('\n')

    def make_stix_bundle(self):
        """
        Create an empty STIX 2.0 bundle to populate with objects.
        :return:
        """
        bundle = {
            'type': 'bundle',
            'id': f'bundle--{str(uuid.uuid4())}',
            'spec_version': '2.0',
            'objects': []
        }

        self.stix_bundle = bundle

    def make_amitt_tactic(self):
        """
        {
            'created_by_ref': 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5',
            'description': 'The adversary is trying to gather data of interest to their goal.\n\nCollection consists of techniques adversaries may use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the data. Common target sources include various drive types, browsers, audio, video, and email. Common collection methods include capturing screenshots and keyboard input.',
            'type': 'x-mitre-tactic',
            'id': 'x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe',
            'object_marking_refs': [
                'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'
            ],
            'name': 'Collection',
            'external_references': [
                {
                    'external_id': 'TA0009',
                    'source_name': 'mitre-attack',
                    'url': 'https://attack.mitre.org/tactics/TA0009'
                }
            ],
            'x_mitre_shortname': 'collection',
            'modified': '2019-07-19T17:44:53.176Z',
            'created': '2018-10-17T00:14:20.652Z'
        },
        :return:
        """
        # Tactics format:
        # [['TA01', 'Strategic Planning', 'P01', 1, 'Defining the desired end state...', ...]]
        tactics = self.tactics.values.tolist()

        for tac in tactics:
            tactic = {}
            tactic['created_by_ref'] = f'identity--{self.stix_created_by}'
            tactic['description'] = f'{tac[4]}'
            tactic['type'] = 'x-mitre-tactic'
            tactic['id'] = f'x-mitre-tactic--{str(uuid.uuid4())}'
            tactic['object_marking_refs'] = [
                f'marking-definition--{self.stix_marking_definition}'
            ]
            tactic['name'] = f'{tac[1]}'
            tactic['external_references'] = [
                {
                    'external_id': f'{tac[4]}',
                    'source_name': 'amitt-attack',
                    'url': f'https://github.com/misinfosecproject/amitt_framework/blob/master/tactics/{tac[0]}.md'
                }
            ]
            tactic['x_mitre_shortname'] = f'{tac[1]}'
            tactic['modified'] = f'{self.stix_creation_timestamp}'
            tactic['created'] = f'{self.stix_creation_timestamp}'

            self.stix_bundle['objects'].append(tactic)


    def make_amitt_technique(self):
        """
        {
            'external_references': [
                {
                    'url': 'https://github.com/misinfosecproject/amitt_framework/blob/master/techniques/T0007.md',
                    'source_name': 'amitt-technique',
                    'external_id': 'T1025'
                }
            ],
            'object_marking_refs': [
                'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'
            ],
            'x_mitre_system_requirements': [
                'Privileges to access removable media drive and files'
            ],
            'x_mitre_data_sources': [
                'File monitoring',
                'Process monitoring',
                'Process command-line parameters'
            ],
            'modified': '2018-10-17T00:14:20.652Z',
            'x_mitre_detection': 'Monitor processes and command-line arguments for actions that could be taken to collect files from a system's connected removable media. Remote access tools with built-in features may interact directly with the Windows API to gather data. Data may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1086).',
            'created_by_ref': 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5',
            'x_mitre_platforms': [
                'Linux',
                'macOS',
                'Windows'
            ],
            'kill_chain_phases': [
                {
                    'phase_name': 'collection',
                    'kill_chain_name': 'mitre-attack'
                }
            ],
            'id': 'attack-pattern--1b7ba276-eedc-4951-a762-0ceea2c030ec',
            'name': 'Data from Removable Media',
            'created': '2017-05-31T21:30:31.584Z',
            'x_mitre_version': '1.0',
            'type': 'attack-pattern',
            'description': 'Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration.\n\nAdversaries may search connected removable media on computers they have compromised to find files of interest. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information. Some adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on removable media.'
        },
        :return:
        """
        # Techniques format:
        # ['T0001', '5Ds (dismiss, distort, distract, dismay, divide)', 'TA01', '4Ds of propaganda ...'], ...]
        techniques = self.techniques.values.tolist()

        for tech in techniques:
            technique = {}
            technique['external_references'] = [
                {
                    'external_id': f'{tech[0]}',
                    'source_name': 'amitt-attack',
                    'url': f'https://github.com/misinfosecproject/amitt_framework/blob/master/techniques/{tech[0]}.md'
                }
            ]
            technique['object_marking_refs'] = [
                f'marking-definition--{self.stix_marking_definition}'
            ]
            technique['modified'] = f'{self.stix_creation_timestamp}'
            technique['created_by_ref'] = f'identity--{self.stix_created_by}'
            technique['kill_chain_phases']: [
                {
                    'phase_name': f'{self.tacdict[tech[2]]}',
                    'kill_chain_name': 'amitt-attack'
                }
            ]
            technique['id'] = f'attack-pattern--{str(uuid.uuid4())}'
            technique['name'] = f'{tech[1]}'
            technique['created'] = f'{self.stix_creation_timestamp}'
            technique['x_mitre_version'] = '3.0'
            technique['type'] = 'attack-pattern'
            technique['description'] = f'{tech[3]}'

            self.stix_bundle['objects'].append(technique)

    def make_amitt_investigation(self):
        pass




def main():
    amitt = Amitt()

    # print(amitt.tactics)
    # print(amitt.tactics.values.tolist())
    # print(amitt.techniques.values.tolist())

    amitt.make_stix_bundle()
    amitt.make_amitt_tactic()
    amitt.make_amitt_technique()

    amitt.write_amitt_file('amitt-attack.json', amitt.stix_bundle)



if __name__ == '__main__':
    main()
