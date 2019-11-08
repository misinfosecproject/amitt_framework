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
import xlrd
from datetime import datetime
from dateutil import parser
import numpy as np
from stix2 import (Bundle, AttackPattern, Indicator, IntrusionSet, Relationship, Sighting, CustomObject, properties,
                   Malware, Campaign, CourseOfAction, Identity, ObservedData, TimestampConstant, MarkingDefinition,
                   StatementMarking, ExternalReference)
from stix2.properties import (IntegerProperty, ListProperty, StringProperty, TimestampProperty)

@CustomObject('x-mitre-tactic', [
    ('name', properties.StringProperty(required=True)),
    ('description', properties.StringProperty(required=True)),
    ('x_mitre_shortname', properties.StringProperty(required=True))
])
class Tactic(object):
    def __init__(self, x_mitre_shortname=None, **kwargs):
        if x_mitre_shortname and x_mitre_shortname not in ["strategic-planning", "objective-planning", "develop-people",
                                           "develop-networks", "microtargeting", "develop-content",
                                           "channel-selection", "pump-priming", "exposure", "go-physical",
                                           "persistence", "measure-effectiveness"]:
            raise ValueError("'%s' is not a recognized AMITT Tactic." % x_mitre_shortname)

@CustomObject('x-mitre-matrix', [
    ('name', StringProperty(required=True)),
    ('description', StringProperty(required=True)),
    ('tactic_refs', ListProperty(StringProperty, required=True))
])
class Matrix(object):
    def __init__(self, **kwargs):
        if True:
            pass

# @CustomObject('x-amitt-influence', [
#     ('name', StringProperty(required=True)),
#     ('description', StringProperty(required=True)),
#     ('published', StringProperty()),
#     ('first_seen', TimestampProperty()),
#     ('last_seen', TimestampProperty()),
#     ('confidence', IntegerProperty()),
#     ('x_source', StringProperty()),
#     ('x_target', StringProperty()),
#     ('x_identified_via', StringProperty())
# 
# ])
# class Influence(object):
#     def __init__(self, **kwargs):
#         if True:
#             pass

class AmittStix2:
    def __init__(self, infile='amitt_metadata_v3.xlsx'):
        self.stix_objects = []
        self.stix_tactic_uuid = {}
        self.stix_technique_uuid = {}
        self.stix_incident_uuid = {}
        self.stix_campaign_uuid = {}
        self.stix_relationship_uuid = {}
        self.identity = None
        self.marking_definition = None

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
        self.it = self.create_incident_technique_crosstable(metadata['incidenttechniques'])


        tactechs = self.techniques.groupby('tactic')['id'].apply(list).reset_index().rename({'id': 'techniques'},
                                                                                            axis=1)
        self.tactics = metadata['tactics'].merge(tactechs, left_on='id', right_on='tactic', how='left').fillna('').drop(
            'tactic', axis=1)

        self.phasedict = self.make_object_dict(self.phases)
        self.tacdict = self.make_object_dict(self.tactics)
        self.techdict = self.make_object_dict(self.techniques)

        self.incidents = self.incidents.replace(np.nan, '', regex=True)
        self.it = self.it.replace(np.nan, '', regex=True)

    def create_incident_technique_crosstable(self, it_metadata):
        # Generate full cross-table between incidents and techniques

        it = it_metadata
        it.index=it['id']
        it = it['techniques'].str.split(',').apply(lambda x: pd.Series(x)).stack().reset_index(level=1, drop=True).to_frame('technique').reset_index().merge(it.drop('id', axis=1).reset_index()).drop('techniques', axis=1)
        it = it.merge(self.incidents[['id','name']],
                      left_on='incident', right_on='id',
                      suffixes=['','_incident']).drop('incident', axis=1)
        it = it.merge(self.techniques[['id','name']],
                      left_on='technique', right_on='id',
                      suffixes=['','_technique']).drop('technique', axis=1)
        return(it)

    def make_object_dict(self, df):
        return pd.Series(df.name.values, index=df.id).to_dict()

    def stix_bundle(self):
        bundle = Bundle(self.stix_objects)
        return bundle

    def stix_marking_definition(self):
        marking_definition = MarkingDefinition(
            definition_type="statement",
            created_by_ref=self.identity,
            definition=StatementMarking(statement="CC-BY-4.0 Misinfosec Project")
        )
        return marking_definition

    def stix_identity(self):
        id = Identity(
            name="Misinfosec Project",
            identity_class="organization",
            description="The Misinfosec group is where misinformation and information security people meet and learn from each other.",
        )
        return id

    def make_amitt_tactic(self):
        """

        """
        # Tactics format:
        # [['TA01', 'Strategic Planning', 'P01', 1, 'Defining the desired end state...', ...]]
        tactics = self.tactics.values.tolist()

        for tac in tactics:
            description = f'{tac[4]}'
            external_references = [
                {
                    'external_id': f'{tac[0]}',
                    'source_name': 'mitre-attack',
                    'url': f'https://github.com/misinfosecproject/amitt_framework/blob/master/tactics/{tac[0]}.md'
                }
            ]
            name = f'{tac[1]}'
            x_mitre_shortname = f'{tac[1]}'.replace(' ', '-').lower()

            tactic = Tactic(
                name=name,
                description=description,
                x_mitre_shortname=x_mitre_shortname,
                external_references=external_references,
                object_marking_refs=self.marking_definition,
                created_by_ref=self.identity
                )
            self.stix_objects.append(tactic)

            # Map the tactic external ID to the x-mitre-tactic uuid for use in x-mitre-matrix.
            self.stix_tactic_uuid[tac[0]] = tactic.id

    def make_amitt_technique(self):
        """

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

            description = f'{tech[3]}'
            external_references = [
                {
                    'external_id': f'{tech[0]}',
                    'source_name': 'mitre-attack',
                    'url': f'https://github.com/misinfosecproject/amitt_framework/blob/master/techniques/{tech[0]}.md'
                }
            ]
            kill_chain_phases = [
                {
                    'phase_name': self.tacdict[tech[2]].replace(' ', '-').lower(),
                    'kill_chain_name': 'mitre-attack'
                }
            ]
            name = f'{tech[1]}'
            x_mitre_platforms = [
                                 "Cyber",
                                 "Physical"
                                ],
            x_mitre_version = '1.0'

            technique = AttackPattern(
                name=name,
                description=description,
                external_references=external_references,
                object_marking_refs=self.marking_definition,
                created_by_ref=self.identity,
                kill_chain_phases=kill_chain_phases,
                custom_properties={
                    'x_mitre_platforms': x_mitre_platforms,
                    'x_mitre_version': x_mitre_version
                }

            )

            self.stix_objects.append(technique)

            self.stix_technique_uuid[tech[0]] = technique.id

    def make_amitt_intrusion_set(self):
        reference = {
                'external_id': '',
                'source_name': '',
                'url': ''
            }

        intrusion_sets = self.incidents.itertuples()
        for i in intrusion_set:
            external_references = []
            if i.type == "campaign":
                reference_copy = reference

                refs = i._8.split(" ")
                print(refs)
                for url in refs:

                    reference_copy['url'] = url
                    external_references.append(reference_copy)

                campaign = IntrusionSet(
                    name=i.name,
                    description=i.summary,
                    first_seen=datetime.strptime(str(int(i._5)), "%Y"),
                    external_references=external_references,
                    custom_properties={
                        "x_published": i._10,
                        "x_source": i._6,
                        "x_target": i._7,
                        "x_identified_via": i._11
                    }
                )
                self.stix_objects.append(campaign)
                self.stix_campaign_uuid[i.id] = campaign.id

    def make_amitt_influence_campaigns(self):
        """
        Pandas(Index=19, id='I00020', name='3000 tanks', type='incident',
        summary=nan, _5="Year Started", _6='From country', _7='To country',
        _8='URL(s)',
        Notes=nan, _10='When added', _11='Found via')
        :return:
        """
        reference = {
            'external_id': '',
            'source_name': '',
            'url': ''
        }

        incidents = self.incidents.itertuples()
        for i in incidents:
            external_references = []
            if i.type == "incident":
                reference_copy = reference

                refs = i._8.split(" ")
                print(refs)
                for url in refs:
                    reference_copy['url'] = url
                    external_references.append(reference_copy)

                campaign = Campaign(
                    name=i.name,
                    description=i.summary,
                    # published=i._10,
                    first_seen=datetime.strptime(str(int(i._5)), "%Y"),
                    # last_seen=,
                    # confidence=,
                    # x_source=i._6,
                    # x_target=i._7,
                    # x_identified_via=i._11,
                    custom_properties={
                        "x_published": i._10,
                        "x_source": i._6,
                        "x_target": i._7,
                        "x_identified_via": i._11
                    },
                    external_references=external_references
                 )
                self.stix_objects.append(campaign)
                self.stix_campaign_uuid[i.id] = campaign.id

    def make_incident_relationships(self):
        for i in self.it.itertuples():
            # print(i)
            if i.id_incident in self.stix_incident_uuid:
                # print(self.stix_incident_uuid)
                source = self.stix_incident_uuid[i.id_incident]
                # print(source)
                target = self.stix_technique_uuid[i.id_technique]
                relation = "uses"

                relationship = Relationship(
                    source_ref=source,
                    target_ref=target,
                    relationship_type=relation
                )
                self.stix_objects.append(relationship)
                self.stix_relationship_uuid[i.id] = relationship.id

    def make_campaign_relationships(self):
        for i in self.it.itertuples():
            # print(i)
            if i.id_incident in self.stix_campaign_uuid:
                # print(self.stix_incident_uuid)
                source = self.stix_campaign_uuid[i.id_incident]
                # print(source)
                target = self.stix_technique_uuid[i.id_technique]
                relation = "uses"

                relationship = Relationship(
                    source_ref=source,
                    target_ref=target,
                    relationship_type=relation
                )
                self.stix_objects.append(relationship)
                self.stix_relationship_uuid[i.id] = relationship.id


    def make_amitt_matrix(self):
        """

        """
        description = 'Adversarial Misinformation and Influence Tactics and Techniques'
        external_references = [
            {
                "external_id": "amitt-attack",
                "source_name": "amitt-attack",
                "url": "https://github.com/misinfosecproject/amitt_framework"
            }
        ]
        name = 'AMITT Misinformation Framework'
        tactic_refs = [
            v for k, v in self.stix_tactic_uuid.items()
        ]

        matrix = Matrix(
            name=name,
            description=description,
            external_references=external_references,
            tactic_refs=tactic_refs
        )
        self.stix_objects.append(matrix)

    def write_amitt_file(self, fname, file_data):
        """
        Write a sorted JSON object to disk.  Note file name args are unique each run.
        :param fname: bundle['objects']['id']
        :param file_data: bundle
        :return:
        """
        with open(fname, 'w') as f:
            # json.dump(file_data, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write(file_data.serialize(pretty=True))
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

    def make_cti_file(self, stix_objects, bundle_name):
        for object in stix_objects:
            self.write_amitt_cti_dir(object.type)
            # Write the bundle to the amitt-attack directory.
            self.write_amitt_file(f"amitt-attack/{object.type}/{object.id}.json", Bundle(object))

        self.write_amitt_file(f"amitt-attack/{bundle_name}.json", self.stix_bundle())


def main():
    stix_maker = AmittStix2()
    stix_maker.identity = stix_maker.stix_identity()
    stix_maker.marking_definition = stix_maker.stix_marking_definition()

    stix_maker.make_amitt_tactic()

    stix_maker.make_amitt_technique()

    stix_maker.make_amitt_matrix()

    stix_maker.make_amitt_influence_incidents()

    stix_maker.make_amitt_intrusion_set()

    stix_maker.make_incident_relationships()

    stix_maker.make_campaign_relationships()

    print(stix_maker.stix_bundle())

    stix_maker.make_cti_file(stix_maker.stix_objects, bundle_name='amitt_attack')






if __name__ == '__main__':
    main()
