# Credibility Coalition AMITT Framework

* [Framework diagram](matrix.md)
* [List of incidents](incidents.md)

AMITT (Adversarial Misinformation and Influence Tactics and Techniques) is a framework designed for describing and understanding disinformation incidents.  AMITT is part of misinfosec - work on adapting information security (infosec) practices to help track and counter misinformation, and is designed as far as possible to fit existing infosec practices and tools. 

AMITT's style is based on the [MITRE ATT&amp;CK framework](https://github.com/mitre-attack/attack-website/); we're working on generating STIX templates for all its objects so it can be passed between ISAOs and similar bodies using standards like TAXI. 

## How this works

The framework is shown in [Framework diagram](matrix.md). Its entities are:
* Tactics: stages that someone running a misinformation incident is likely to use
* Techniques: activities that might be seen at each stage
* Tasks: things that need to be done at each stage.  In Pablospeak, tasks are things you do, techniques are how you do them. 
* Phases: higher-level groupings of tactics, created so we could check we didn't miss anything

There's a directory for each of these entities, containing a datasheet for each individual entity (e.g. [technique T0046 Search Engine Optimization](techniques/T0046.md)).  The details above "DO NOT EDIT ABOVE THIS LINE" are generated from the code and spreadsheet in folder generating_code, which you can use to update framework metadata; you can add notes below "DO NOT EDIT ABOVE THIS LINE" and they won't be removed when you do metadata updates.  (Yes, this is an unholy hack, but it's one that lets us generate all the messages we need, and keep notes in the same place.)

The framework was created by finding and analysing a set of existing misinformation [incidents](incidents.md), which also have room for more notes.

## Provenance

AMITT was created by the Credibilty Coalition's [Misinfosec working group](https://github.com/credcoalition/community-site/wiki/Working-Groups), which is the standards group connected to Misinfosec.  We would love any and all suggestions for improvements, comments and offers of help via the issues list on this github. 

AMITT is licensed under [CC-BY-4.0](LICENSE.md)