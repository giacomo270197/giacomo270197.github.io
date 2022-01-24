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

A `run` method must also be implemented. This is the method that will be called when the plugin is invoked, a it must return a `TreeGrid` structure, which Volatility will then take care of pretty printing. The `TreeGrid` structure, however, if generally populated by a `_generator` method, which is then where the work really takes place. Here's the `run` method for my class.

```python
def run(self):
    return renderers.TreeGrid([("Content", str)], self._generator())
```

Moving on, the first task to accomplish is to find the right process to work on. This is done though the `pslist` plugin, and I feel this is one of those situations where Volatility documentation could use some love. The `pslist` plugin implements the `PsList` class, which returns a `TreeGrid` as a result of its `run` method, like all plugins have to. However the pretty text representation isn't what you want when processing `pslist` output. Instead, you want a iterable object containing `EPROCESS` objects (Volatility internal representation of a process). This can be achieved with a `list_processes` function defined in `PsList` which is not documented anywhere. In order to understand how the function worked, and what to pass to it as arguments, I had to dig through the implementation of other plugins to find.
In any event, the function takes `self.context` (not sure what this is), the memory translation layer, the symbols, and a filter function callback as arguments. After some digging, I found out that the filter function is basically meant to return `True` when something is passed to it that we want to exclude. In other implementation this is used, for example, to exclude PIDs from processing. In our case we don't want to do any filtering so the function always returns `False`.
After that, each `EPROCESS` is checked to see if the `ImageFileName` (aka the name of the file on disk the process was started from) matches "notepad.exe". If so, the `EPROCESS` object is returned. Some casting is needed to convert the `ImageFileName` attribute to native python strings.

```python
def filter_func(self, x):
    False

def find_PID(self):
    procs = pslist.PsList.list_processes(self.context, self.config['primary'],  self.config['nt_symbols'],  filter_func = self.filter_func)
    for proc in procs:
        name = proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace')
        if name == "notepad.exe":
            return proc      
```

Now that we have out process object at hand, we need to list out all the VADs for it. This can be done with the `vadinfo` plugin. For each VAD we get some useful info such as the start, end, permissions, file on disk mapped in memory (if present), ...

<a href="/assets/images/volatility/vadinfo.png"><img src="/assets/images/volatility/vadinfo.png" margin="0 250px 0" width="100%"/></a>

The `VadInfo` class in the `vadinfo` plugin implements the `list_vads` method, which takes an `EPROCESS` and a filter function as arguments, and returns a list of VAD objects. The filter function works the same as the one for `list_processes`.

```python
def get_VADs(self, proc):
    return vadinfo.VadInfo.list_vads(proc, filter_func = self.filter_func)
```