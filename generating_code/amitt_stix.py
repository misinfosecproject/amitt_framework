# Convert the amitt_metadata_v3.xlsx file to STIX bundle.
#
# This tool is part of the misinfosec project and released under the GNU Affero
# General Public License v3.0
#
# Copyright (C) 2019 Roger Johnston

from datetime import datetime
import pandas as pd
import os
import re
import json
import xlrd
from datetime import datetime
from dateutil import parser
import numpy as np
from stix2 import (Bundle, AttackPattern, ThreatActor, IntrusionSet, Relationship, CustomObject, properties,
                   Malware, Tool, Campaign, Identity, MarkingDefinition, ExternalReference, StatementMarking,
                   GranularMarking)
from stix2.properties import (ReferenceProperty, ListProperty, StringProperty, TimestampProperty)

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

@CustomObject('x-amitt-narrative', [
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('aliases', ListProperty(StringProperty)),
    ('first_seen', TimestampProperty()),
    ('last_seen', TimestampProperty()),
    ('objective', StringProperty()),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.0'))),
    ('granular_markings', ListProperty(GranularMarking))
])
class Narrative(object):
    def __init__(self, **kwargs):
        if True:
            pass

@CustomObject('x-amitt-incident', [
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('aliases', ListProperty(StringProperty)),
    ('first_seen', TimestampProperty()),
    ('last_seen', TimestampProperty()),
    ('objective', StringProperty()),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.0'))),
    ('granular_markings', ListProperty(GranularMarking))
])
class Incident(object):
    def __init__(self, **kwargs):
        if True:
            pass

@CustomObject('x-mitre-matrix', [
    ('name', StringProperty(required=True)),
    ('description', StringProperty(required=True)),
    ('tactic_refs', ListProperty(StringProperty, required=True))
])
class Matrix(object):
    def __init__(self, **kwargs):
        if True:
            pass


class AmittStix:
    def __init__(self, infile='amitt_metadata_v3.xlsx'):
        self.stix_objects = []
        self.stix_tactic_uuid = {}
        self.stix_technique_uuid = {}
        self.stix_intrusion_set_uuid = {}
        self.stix_campaign_uuid = {}
        self.stix_threat_actor_uuid = {}
        self.stix_identity_uuid = {}
        self.stix_incident_uuid = {}
        self.stix_relationship_uuid = {}
        self.identity = None
        self.marking_definition = None

        # Load metadata from file
        metadata = {}
        xlsx = pd.ExcelFile(infile)
        for sheetname in xlsx.sheet_names:
            metadata[sheetname] = xlsx.parse(sheetname)

        # Create individual tables and dictionaries
        self.actors = metadata['actors']
        self.campaigns = metadata['campaigns']
        self.intrusionsets = metadata['intrusionsets']
        self.identities = metadata['identities']
        self.incidents = metadata['incidents']
        self.phases = metadata['phases']
        self.tasks = metadata['tasks']
        self.techniques = metadata['techniques']
        self.relationships = metadata['relationships']
        self.it = self.expand_relationship_targets(metadata['relationships'])

        tactechs = self.techniques.groupby('tactic')['id'].apply(list).reset_index()\
            .rename({'id': 'techniques'}, axis=1)
        self.tactics = metadata['tactics'].merge(tactechs, left_on='id', right_on='tactic',
                                                 how='left').fillna('').drop('tactic', axis=1)
        self.tacdict = self.make_object_dict(self.tactics)

        self.actors = self.actors.replace(np.nan, '', regex=True)
        self.incidents = self.incidents.replace(np.nan, '', regex=True)
        self.identities = self.identities.replace(np.nan, '', regex=True)
        self.campaigns = self.campaigns.replace(np.nan, '', regex=True)
        self.intrusionsets = self.intrusionsets.replace(np.nan, '', regex=True)
        self.relationships = self.relationships.replace(np.nan, '', regex=True)
        self.it = self.it.replace(np.nan, '', regex=True)

    def expand_relationship_targets(self, it_metadata):
        it = it_metadata
        it.index = it['id']
        it = it['targets'].str.split(',').apply(lambda x: pd.Series(x)).stack().reset_index(level=1,
                                                                                               drop=True).to_frame(
            'target').reset_index().merge(it.drop('id', axis=1).reset_index()).drop('targets', axis=1)

        return it

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

    def parse_xlsx_reference_tuples(self, t):
        refs = []
        ref_tuples = re.findall("([^()]+)", t)

        for i in ref_tuples:
            s = i.split(",")
            ref_list = []
            for n in s:
                ref_list.append(n.strip(" "))

            if ref_list == [""]:
                continue
            else:
                refs.append(ref_list)

        return refs

    def amitt_tactic(self):
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

    def amitt_technique(self):
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

    def amitt_intrusion_set(self):
        """

        """
        intrusion_sets = self.intrusionsets.itertuples()
        for i in intrusion_sets:
            if i.id == "I00000":
                continue
            external_references = []
            if i.type == "intrusion-set":
                refs = self.parse_xlsx_reference_tuples(i.references)
                for ref in refs:
                    try:
                        reference = ExternalReference(
                            source_name=ref[1],
                            url=ref[2],
                            external_id=ref[0]
                        )
                        external_references.append(reference)
                    except IndexError:
                        pass

                try:
                    created_date = datetime.strptime(i.whenAdded, "%Y-%m-%d")
                except:
                    created_date = datetime.now()

                intrusion_set = IntrusionSet(
                    name=i.name,
                    description=i.summary,
                    first_seen=datetime.strptime(str(int(i.firstSeen)), "%Y"),
                    created=created_date,
                    custom_properties={
                        # "x_published": i.whenAdded,
                        # "x_source": i.sourceCountry,
                        # "x_target": i.targetCountry,
                        "x_identified_via": i.foundVia
                    },
                    external_references=external_references
                )
                self.stix_objects.append(intrusion_set)
                self.stix_intrusion_set_uuid[i.id] = intrusion_set.id

    def amitt_incident(self):
        """

        """
        incidents = self.incidents.itertuples()
        for i in incidents:
            print(i)
            if i.id == "I00000":
                continue
            external_references = []
            print(i.type)
            if i.type == "incident":
                refs = self.parse_xlsx_reference_tuples(i.references)
                for ref in refs:
                    try:
                        reference = ExternalReference(
                            source_name=ref[1],
                            url=ref[2],
                            external_id=ref[0]
                        )
                        external_references.append(reference)
                    except IndexError:
                        pass

                try:
                    created_date = datetime.strptime(i.whenAdded, "%Y-%m-%d")
                except:
                    created_date = datetime.now()

                incident = Incident(
                    name=i.name,
                    description=i.summary,
                    first_seen=datetime.strptime(str(int(i.firstSeen)), "%Y"),
                    created=created_date,
                    custom_properties={
                        # "x_source": i.sourceCountry,
                        # "x_target": i.targetCountry,
                        "x_identified_via": i.foundVia
                    },
                    external_references=external_references
                 )
                self.stix_objects.append(incident)
                self.stix_incident_uuid[i.id] = incident.id

    def amitt_campaign(self):
        """

        """
        campaigns = self.campaigns.itertuples()
        for i in campaigns:
            if i.id == "I00000":
                continue
            external_references = []
            print(i.type)
            if i.type == "campaign":
                refs = self.parse_xlsx_reference_tuples(i.references)
                for ref in refs:
                    try:
                        reference = ExternalReference(
                            source_name=ref[1],
                            url=ref[2],
                            external_id=ref[0]
                        )
                        external_references.append(reference)
                    except IndexError:
                        pass

                try:
                    created_date = datetime.strptime(i.whenAdded, "%Y-%m-%d")
                except:
                    created_date = datetime.now()

                campaign = Campaign(
                    name=i.name,
                    description=i.summary,
                    first_seen=datetime.strptime(str(int(i.firstSeen)), "%Y"),
                    created=created_date,
                    custom_properties={
                        # "x_published": i.whenAdded,
                        # "x_source": i.sourceCountry,
                        # "x_target": i.targetCountry,
                        "x_identified_via": i.foundVia
                    },
                    external_references=external_references
                 )
                self.stix_objects.append(campaign)
                self.stix_campaign_uuid[i.id] = campaign.id

    def amitt_actor(self):
        """

        """
        threat_actors = self.actors.itertuples()
        for i in threat_actors:
            if i.id == "I00000":
                continue
            external_references = []
            print(i.type)
            if i.type == "threat-actor":
                refs = self.parse_xlsx_reference_tuples(i.references)
                for ref in refs:
                    try:
                        reference = ExternalReference(
                            source_name=ref[1],
                            url=ref[2],
                            external_id=ref[0]
                        )
                        external_references.append(reference)
                    except IndexError:
                        pass

                try:
                    created_date = datetime.strptime(i.whenAdded, "%Y-%m-%d")
                except:
                    created_date = datetime.now()

                threat_actor = ThreatActor(
                    name=i.name,
                    description=i.summary,
                    labels=i.labels.split(","),
                    created=created_date,
                    custom_properties={
                        # "x_published": i.whenAdded,
                        # "x_first_seen": datetime.strptime(str(int(i.firstSeen)), "%Y"),
                        # "x_source": i.sourceCountry,
                        # "x_target": i.targetCountry,
                        "x_identified_via": i.foundVia
                    },
                    external_references=external_references
                 )
                self.stix_objects.append(threat_actor)
                self.stix_threat_actor_uuid[i.id] = threat_actor.id

    def amitt_identity(self):
        """

        """
        threat_actors = self.identities.itertuples()
        for i in threat_actors:
            if i.id == "ID00000":
                continue
            external_references = []
            if i.type == "identity":
                refs = self.parse_xlsx_reference_tuples(i.references)
                for ref in refs:
                    try:
                        reference = ExternalReference(
                            source_name=ref[1],
                            url=ref[2],
                            external_id=ref[0]
                        )
                        external_references.append(reference)
                    except IndexError:
                        pass

                try:
                    created_date = datetime.strptime(i.whenAdded, "%Y-%m-%d")
                except:
                    created_date = datetime.now()

                identity = Identity(
                    name=i.name,
                    description=i.summary,
                    identity_class=i.identityClass,
                    sectors=i.sectors,
                    contact_information=i.contactInformation,
                    created=created_date,
                    custom_properties={
                        # "x_published": i.whenAdded,
                        # "x_source": i.sourceCountry,
                        # "x_target": i.targetCountry,
                        "x_identified_via": i.foundVia
                    },
                    external_references=external_references
                 )
                self.stix_objects.append(identity)
                self.stix_identity_uuid[i.id] = identity.id

    def amitt_relationship(self):
        """

        """
        # Merge all UUID dictionaries.
        stix_objects = {**self.stix_campaign_uuid, **self.stix_intrusion_set_uuid, **self.stix_tactic_uuid,
                        **self.stix_identity_uuid, **self.stix_technique_uuid, **self.stix_threat_actor_uuid,
                        **self.stix_incident_uuid}
        for i in self.it.itertuples():
            if i.id == "I00000T000":
                continue

            if i.source in stix_objects and i.target in stix_objects:
                relationship = Relationship(
                    source_ref=stix_objects[i.source],
                    target_ref=stix_objects[i.target],
                    relationship_type=i.relationship
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
    stix_maker = AmittStix()
    stix_maker.identity = stix_maker.stix_identity()
    stix_maker.marking_definition = stix_maker.stix_marking_definition()

    stix_maker.amitt_tactic()

    stix_maker.amitt_technique()

    stix_maker.make_amitt_matrix()

    stix_maker.amitt_incident()

    stix_maker.amitt_campaign()

    stix_maker.amitt_actor()

    stix_maker.amitt_intrusion_set()

    stix_maker.amitt_intrusion_set()

    stix_maker.amitt_identity()

    stix_maker.amitt_relationship()

    # print(stix_maker.stix_bundle())

    stix_maker.make_cti_file(stix_maker.stix_objects, bundle_name='amitt_attack')

if __name__ == '__main__':
    main()
