---
title: Notepad Plugin
permalink: posts/volatility/notepad
permalink_name: Notepad
---

While reading "The Art of Memory Forensics", I came across a plugin the authors wrote to read the text inserted in a Notepad.exe instance off of process memory. While just an example, I figured I would try to implement the plugin myself to make familiarize myself with Volatility internal workings.
There were mainly two issues to overcome:
- An actual plugin implementation is never given in the book, nor can be easily found online,
- The book was written in 2014, and focuses on Volatility 2. I wanted to write my code for Volatility 3, and I wanted it to work on newer version of Windows.

The first thing I needed to do, was to generate a memory dump that I could work off of. In order to do that I just started a notepad instance on a Windows 10 VM, added some text (without saving to disk!) and captured the memory content with FTK Imager.

<a href="/assets/images/volatility/notepad.jpeg"><img src="/assets/images/volatility/notepad.jpeg" margin="0 250px 0" width="100%"/></a>

After obtaining the memory dump, it was time to start writing the plugin. On a general level, the plugin is meant to work the similarly as described in the book. First, it should identify the PID of the process where `ImageBaseFile="notepad.exe"`. Then it should list all of the Virtual Address Descriptors (VAD) for the process, and search them for the text we wrote in Notepad.
VADs are data structures maintained by the Windows OS that "track reserved or committed, virtually contiguous collection of pages". These can basically be thought of as chunks of memory pages used for a common purpose, and containing extra meta-information on top of the raw memory contents.

I created a plugin file under `volatility3/volatility3/plugins/windows/notepad.py` which implements the `ReadNotepad` class. As per Volatility documentation, a plugin class has to inherit from `plugins.PluginInterface` and must implement a `get_requirements` method. Anther requirement I came across, was that the class must contain a `_required_framework_version` attribute, specifying the Volatility 3 version to work with (2.0.0 in my case).
As per the requirements, the following were needed for my plugin:
- `TranslationLayerRequirement`: this specifies that a translation layer is required. As far as my understanding goes, this is a layer that translates actual physical memory content to virtual memory, taking care or reassembling memory that's not necessarily stored contiguously in RAM, but belong to the same virtual memory regions.
- `SymbolTableRequirement`: In my case, this imports the Windows kernel symbols.
- `PluginRequirement`: This lists out the plugins which I wanted to build on. In my case, I needed `pslist` to find the Notepad process PID, and `vadinfo` to list the VADs in our process of interest.

All said and then, this is what the class definition and requirements look like.

```python
class ReadNotepad(plugins.PluginInterface):
    """Gets text off of Notepad heap"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", 
                description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', 
                plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.PluginRequirement(name = 'vadinfo', 
                plugin = vadinfo.VadInfo, version = (2, 0, 0))
            ]
```

