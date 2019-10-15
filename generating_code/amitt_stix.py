# Convert the amitt_metadata_v3.xlsx file to STIX bundle.
#
# This tool is part of the misinfosec project and released under the GNU Affero
# General Public License v3.0
#
# Copyright (C) 2019 Roger Johnston

from datetime import datetime
import pandas as pd
import os
import json
import uuid
import xlrd


class Amitt:
    """

    Create STIX bundles from the AMITT metadata xlsx.

    """

    def __init__(self, infile='amitt_metadata_v3.xlsx'):

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

        tactechs = self.techniques.groupby('tactic')['id'].apply(list).reset_index().rename({'id': 'techniques'},
                                                                                            axis=1)
        self.tactics = metadata['tactics'].merge(tactechs, left_on='id', right_on='tactic', how='left').fillna('').drop(
            'tactic', axis=1)

        self.phasedict = self.make_object_dict(self.phases)
        self.tacdict = self.make_object_dict(self.tactics)
        self.techdict = self.make_object_dict(self.techniques)

        self.stix_bundle = {}
        self.stix_created_by = str(uuid.uuid4())
        self.stix_marking_definition = str(uuid.uuid4())
        self.stix_creation_timestamp = datetime.now().isoformat()
        self.stix_tactic_uuid = {}

    def make_object_dict(self, df):
        return pd.Series(df.name.values, index=df.id).to_dict()

    def write_amitt_file(self, fname, file_data):
        """
        Write a sorted JSON object to disk.  Note file name args are unique each run.
        :param fname: bundle['objects']['id']
        :param file_data: bundle
        :return:
        """
        with open(fname, 'w') as f:
            json.dump(file_data, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write('\n')

    def write_amitt_cti_dir(self, dir):
        """
        Write a directory to disk. A directory name must be the same as the bundle type.
        :param dir: bundle['objects']['type']
        :return:
        """
        try:
            os.mkdir('amitt-attack')
        except FileExistsError:
            pass

        try:
            os.mkdir('amitt-attack/' + dir)
        except FileExistsError:
            pass

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

        return bundle

    def make_amitt_tactic(self):
        """
        Build a tactic bundle as follows.
        {
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "The adversary is ... ",
            "external_references": [
                {
                    "external_id": "TA0008",
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0008"
                }
            ],
            "id": "x-mitre-tactic--7141578b-e50b-4dcc-bfa4-08a8dd689e9e",
            "modified": "2019-07-19T17:44:36.953Z",
            "name": "Lateral Movement",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "type": "x-mitre-tactic",
            "x_mitre_shortname": "lateral-movement"
        }
        :return:
        """
        # Tactics format:
        # [['TA01', 'Strategic Planning', 'P01', 1, 'Defining the desired end state...', ...]]
        tactics = self.tactics.values.tolist()

        for tac in tactics:
            tactic = {}
            tactic['created'] = f'{self.stix_creation_timestamp}'
            tactic['created_by_ref'] = f'identity--{self.stix_created_by}'
            tactic['description'] = f'{tac[4]}'
            tactic['external_references'] = [
                {
                    'external_id': f'{tac[0]}',
                    'source_name': 'mitre-attack',
                    'url': f'https://github.com/misinfosecproject/amitt_framework/blob/master/tactics/{tac[0]}.md'
                }
            ]
            tactic['id'] = f'x-mitre-tactic--{str(uuid.uuid4())}'
            tactic['modified'] = f'{self.stix_creation_timestamp}'
            tactic['name'] = f'{tac[1]}'
            tactic['object_marking_refs'] = [
                f'marking-definition--{self.stix_marking_definition}'
            ]
            tactic['type'] = 'x-mitre-tactic'
            tactic['x_mitre_shortname'] = f'{tac[1]}'.replace(' ', '-').lower()

            self.stix_bundle['objects'].append(tactic)

            self.make_cti_file(tactic)

            # Map the tactic external ID to the x-mitre-tactic uuid for use in x-mitre-matrix.
            self.stix_tactic_uuid[tac[0]] = tactic['id']

    def make_amitt_technique(self):
        """
        {
            "created": "2017-05-31T21:30:22.096Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "Some security tools ...",
            "external_references": [
                {
                    "external_id": "T1009",
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1009"
                }
            ],
            "id": "attack-pattern--519630c5-f03f-4882-825c-3af924935817",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "defense-evasion"
                }
            ],
            "modified": "2019-01-31T19:18:29.228Z",
            "name": "Binary Padding",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "type": "attack-pattern",
            "x_mitre_data_sources": [
                "Binary file metadata",
                "File monitoring",
                "Malware reverse engineering"
            ],
            "x_mitre_defense_bypassed": [
                "Signature-based detection",
                "Anti-virus"
            ],
            "x_mitre_detection": "Depending on the method used to pad ioe file.",
            "x_mitre_platforms": [
                "Linux",
                "macOS",
                "Windows"
            ],
            "x_mitre_version": "1.0"
        }
        :return:
        """
        # Techniques format:
        # ['T0001', '5Ds (dismiss, distort, distract, dismay, divide)', 'TA01', '4Ds of propaganda ...'], ...]
        techniques = self.techniques.values.tolist()

        for tech in techniques:
            if tech[1] != tech[1]:
                tech[1] = ''

            if tech[2] != tech[2]:
                tech[2] = ''

            if tech[3] != tech[3]:
                tech[3] = ''

            if tech[1] == tech[2] == tech[3] == '':
                continue

            technique = {}
            technique['created'] = f'{self.stix_creation_timestamp}'
            technique['created_by_ref'] = f'identity--{self.stix_created_by}'
            technique['description'] = f'{tech[3]}'
            technique['external_references'] = [
                {
                    'external_id': f'{tech[0]}',
                    'source_name': 'mitre-attack',
                    'url': f'https://github.com/misinfosecproject/amitt_framework/blob/master/techniques/{tech[0]}.md'
                }
            ]
            technique['id'] = f'attack-pattern--{str(uuid.uuid4())}'
            technique['kill_chain_phases'] = [
                {
                    'phase_name': self.tacdict[tech[2]].replace(' ', '-').lower(),
                    'kill_chain_name': 'mitre-attack'
                }
            ]
            technique['modified'] = f'{self.stix_creation_timestamp}'
            technique['name'] = f'{tech[1]}'

            technique['object_marking_refs'] = [
                f'marking-definition--{self.stix_marking_definition}'
            ]
            technique['type'] = 'attack-pattern'
            technique['x_mitre_platforms'] = [
                                                 "Linux",
                                                 "macOS",
                                                 "Windows"
                                             ],
            technique['x_mitre_version'] = '1.0'

            self.stix_bundle['objects'].append(technique)

            self.make_cti_file(technique)

    def make_amitt_matrix(self):
        """
        {
          "created": "2018-10-17T00:14:20.652Z",
          "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
          "description": "The full ATT&CK Matrix includes techniques spanning Windows, Mac, and ...",
          "external_references": [
            {
              "external_id": "enterprise-attack",
              "source_name": "mitre-attack",
              "url": "https://attack.mitre.org/matrices/enterprise"
            }
          ],
          "id": "x-mitre-matrix--eafc1b4c-5e56-4965-bd4e-66a6a89c88cc",
          "modified": "2019-04-16T21:39:18.247Z",
          "name": "Enterprise ATT&CK",
          "object_marking_refs": [
            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
          ],
          "tactic_refs": [
            "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
            "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
            "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
            "x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd",
            "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
            "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263",
            "x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9",
            "x-mitre-tactic--7141578b-e50b-4dcc-bfa4-08a8dd689e9e",
            "x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe",
            "x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813",
            "x-mitre-tactic--9a4e74ab-5008-408c-84bf-a10dfbc53462",
            "x-mitre-tactic--5569339b-94c2-49ee-afb3-2222936582c8"
          ],
          "type": "x-mitre-matrix"
        },
        :return:
        """
        matrix = {}
        matrix['created'] = self.stix_creation_timestamp
        matrix['created_by_ref'] = self.stix_created_by
        matrix['description'] = 'Adversarial Misinformation and Influence Tactics and Techniques'
        matrix['external_references'] = [
            {
                "external_id": "amitt-attack",
                "source_name": "amitt-attack",
                "url": "https://github.com/misinfosecproject/amitt_framework"
            }
        ]
        matrix['id'] = f'x-mitre-matrix--{str(uuid.uuid4())}'
        matrix['modified'] = self.stix_creation_timestamp
        matrix['name'] = 'AMITT Misinformation Framework'
        matrix['object_marking_refs'] = [
            f'marking-definition--{self.stix_marking_definition}'
        ]
        matrix['tactic_refs'] = [
            v for k, v in self.stix_tactic_uuid.items()
        ]
        matrix['type'] = 'x-mitre-matrix'

        self.stix_bundle['objects'].append(matrix)

        self.make_cti_file(matrix)

    def make_amitt_identity(self):
        """
        {
            "type": "bundle",
            "id": "bundle--726d4989-0335-4e74-b661-63027e6cd637",
            "spec_version": "2.0",
            "objects": [
                {
                    "modified": "2017-06-01T00:00:00.000Z",
                    "type": "identity",
                    "identity_class": "organization",
                    "object_marking_refs": [
                        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
                    ],
                    "name": "The MITRE Corporation",
                    "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                    "created": "2017-06-01T00:00:00.000Z"
                }
            ]
        }
        :return:
        """
        identity = {}
        identity['created'] = self.stix_creation_timestamp
        identity['id'] = f'identity--{str(uuid.uuid4())}'
        identity['identity_class'] = 'organization'
        identity['modified'] = self.stix_creation_timestamp
        identity['name'] = 'misinfosec project'
        identity['object_marking_refs'] = [f'marking-definition--{self.stix_marking_definition}']
        identity['type'] = 'identity'

        self.stix_bundle['objects'].append(identity)

        self.make_cti_file(identity)

    def make_amitt_marking_definition(self):
        """
        {
            "type": "bundle",
            "id": "bundle--71bbd1e8-7423-4a2d-8e95-fd73c229a96d",
            "spec_version": "2.0",
            "objects": [
                {
                    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                    "type": "marking-definition",
                    "definition": {
                        "statement": "Copyright 2017, The MITRE Corporation"
                    },
                    "definition_type": "statement",
                    "created": "2017-06-01T00:00:00Z",
                    "id": "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
                }
            ]
        }
        :return:
        """
        marking = {}
        marking['created'] = self.stix_creation_timestamp
        marking['created_by_ref'] = self.stix_created_by
        marking['definition'] = {'statement': 'CC-BY-4.0 misinfosec project'}
        marking['definition_type'] = 'statement'
        marking['id'] = f'marking-definition--{str(uuid.uuid4())}'
        marking['type'] = 'marking-definition'

        self.stix_bundle['objects'].append(marking)

        self.make_cti_file(marking)

    def make_cti_file(self, stix_object):
        # Create the STIX tactic bundle.
        bundle = self.make_stix_bundle()

        # Add the tactic object to the bundle.
        bundle['objects'].append(stix_object)

        # Write the amitt-attack property directory.
        self.write_amitt_cti_dir(stix_object['type'])

        # Write the bundle to the amitt-attack directory.
        self.write_amitt_file(f"amitt-attack/{stix_object['type']}/{stix_object['id']}", bundle)


def main():
    amitt = Amitt()
    amitt.stix_bundle = amitt.make_stix_bundle()
    amitt.make_amitt_tactic()
    amitt.make_amitt_technique()
    amitt.make_amitt_identity()
    amitt.make_amitt_marking_definition()
    amitt.make_amitt_matrix()

    amitt.write_amitt_file('amitt-attack/amitt-attack.json', amitt.stix_bundle)


if __name__ == '__main__':
    main()
