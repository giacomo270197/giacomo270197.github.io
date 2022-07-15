---
title: File Tracing Driver
permalink: /posts/kernelDevelopement/FileTracingDriver
permalink_name: filetracingdriver
---

I recently picked up an interest in writing Windows kernel drivers. I am not sure whether kernel-level malware still exists, and how common it might be, but lots of security software such as EDRs run at least some code in kernel-mode. Moreover, I just wanted to get more familiar with the insides of Windows, so I went and picked up "Windows Kernel Programming" from Pavel Yosifovich. If you are completely new to kernel programming and looking to learn something to get you started, this is an awesome resource!
So after going through the book, I was very interested in the filtering options the book gave because I figured they could be used to trace the actions a program carries out (basically, what Procmon does), so I decided to go ahead and implement something along that way, starting with tracing filesystem events. The project can be found [on my Github page](https://github.com/giacomo270197/Windows-Drivers-Experiments/tree/main/Tracing%20Driver).

To carry out filesystem event filtering (monitoring, in this case, look at this as a filter that only logs) I decided to use filesystem mini-filters. Mini-filters operate differently than other drivers, they are managed by the Filter Manager driver, which is the one receiving the I/O Request Package (IRP) about a certain filesystem request. The Filter Manager then calls upon the mini-filter stack to filter the request either before it's executed (pre-operation callback) or after (post-operation callback). The mini-filters are not responsible for handling the IRP. Note that there might be several instances of the filter object running at any given time. Each volume can have its filter attached to it. There are ways to programmatically decide which volume your filter will attach to, but in this case, we want it to attach to everything (and therefore log everything).

The request traverses the mini-filter stack (or stacks, there could be more if a legacy filesystem driver also exists), from the top to the bottom. The mini-filter position in the stack is defined by its "Altitude", more on this later. First, the filter manager checks if any mini-filter registered any pre-operation callback for the particular action that is being carried out. If so, the callback is invoked. Since this happens before the actual filesystem action pre-operation callbacks have the power to modify or outright stop incoming filesystem operations. After the filesystem action is finished, the filter manager checks for post-operation callbacks in the same fashion. Since these callbacks run after the operation they cannot modify the request, but they can inspect the results.

A mini-filter is registered once by calling the `FltRegisterFilter` API function, which has the following prototype.

```c
NTSTATUS FLTAPI FltRegisterFilter(
  [in]  PDRIVER_OBJECT         Driver,
  [in]  const FLT_REGISTRATION *Registration,
  [out] PFLT_FILTER            *RetFilter
);
```
This is generally the first thing you want to do, so if your driver is registering a mini-filter you'd expect to see this in `DriverEntry`. The `Driver` and `RetFilter` parameters are the driver object and an opaque pointer to the filter object. The first is given as an argument to `DriverEntry` and the second is an output value. The `Registration` parameter, on the other hand, is more interesting and it is the way we "tell" the filter what it is supposed to be doing. It is of type `FLT_REGISTRATION` prototyped as follows.

```c
typedef struct _FLT_REGISTRATION {
  USHORT                                      Size;
  USHORT                                      Version;
  FLT_REGISTRATION_FLAGS                      Flags;
  const FLT_CONTEXT_REGISTRATION              *ContextRegistration;
  const FLT_OPERATION_REGISTRATION            *OperationRegistration;
  PFLT_FILTER_UNLOAD_CALLBACK                 FilterUnloadCallback;
  PFLT_INSTANCE_SETUP_CALLBACK                InstanceSetupCallback;
  PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK       InstanceQueryTeardownCallback;
  PFLT_INSTANCE_TEARDOWN_CALLBACK             InstanceTeardownStartCallback;
  PFLT_INSTANCE_TEARDOWN_CALLBACK             InstanceTeardownCompleteCallback;
  PFLT_GENERATE_FILE_NAME                     GenerateFileNameCallback;
  PFLT_NORMALIZE_NAME_COMPONENT               NormalizeNameComponentCallback;
  PFLT_NORMALIZE_CONTEXT_CLEANUP              NormalizeContextCleanupCallback;
  PFLT_TRANSACTION_NOTIFICATION_CALLBACK      TransactionNotificationCallback;
  PFLT_NORMALIZE_NAME_COMPONENT_EX            NormalizeNameComponentExCallback;
  PFLT_SECTION_CONFLICT_NOTIFICATION_CALLBACK SectionNotificationCallback;
} FLT_REGISTRATION, *PFLT_REGISTRATION;
```

Most of these fields are no use to us and therefore I won't spend much time on them. `Size`, `Version`, and `Flags` are usually constant, check out the code in my repository to see how to fill them out. The `ContextRegistration` is a useful property that can be used to store information about a file to be persisted across mini-filter callbacks. We will not use it in this example. `OperationRegistration` is the most important entry and it stores the callback registration. The other functions are not as useful for us, they are used for a multitude of functionalities such as deciding what volumes to attach to, what to do when a volume is detached, ... 

So how do we tell the filter which callback functions to call when a filesystem operation happens? The `OperationRegistration` parameter of `Registration` lets us pass an array of `FLT_OPERATION_REGISTRATION` structs

```c
typedef struct _FLT_OPERATION_REGISTRATION {
  UCHAR                            MajorFunction;
  FLT_OPERATION_REGISTRATION_FLAGS Flags;
  PFLT_PRE_OPERATION_CALLBACK      PreOperation;
  PFLT_POST_OPERATION_CALLBACK     PostOperation;
  PVOID                            Reserved1;
} FLT_OPERATION_REGISTRATION, *PFLT_OPERATION_REGISTRATION;
```

As per the prototype, each instance of this struct allows us to register one or two callbacks according to specific parameters:
- MajorFunction: what action is being carried out, that can be `IRP_MJ_CREATE` (file open or create), `IRP_MJ_READ`, `IRP_MJ_WRITE`, ...
- Flags: Not important in this case, just fill in 0
- PreOperation: The pre-callback for this major function, NULL for no pre-callback
- PostOperation: The post-callback for this major function, NULL for no pre-callback

We are going to try to monitor `IRP_MJ_CREATE`. That's the one that makes the most sense since it always happens once for each file a process wants to interact with. We could theoretically use both a pre- or post-operation callback for this, however, one might imagine that if we use a pre- callback some other mini-filter registered below ours could stop the request, leaving us with a log for an operation that never actually happened. Also, using a post- callback would allow us to check for the operation result. All that considered, using a post-operation callback registration sounds like a better option. Here you can see how I filled in the `FLT_REGISTRATION` entry.

```c
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, nullptr, TracerCreateLog},
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	nullptr,
	Callbacks,
	TracerMiniFilterUnload,
	PfltInstanceSetupCallback,
	TracerMiniFilterQueryTeardown,
	TracerMiniFilterInstanceTeardownStart,
	TracerMiniFilterInstanceTeardownComplete
};
```

And with that, we can go ahead and register our filter

```c
status = FltRegisterFilter(DriverObject, &FilterRegistration, &filterHandle);
if (!NT_SUCCESS(status)) {
    KdPrint(("Failed to register filesystem mini-filter\n"));
    return status;
}
```

As you can see in the code, the filter only registers a single post-operation callback, `TracerCreateLog`. The callback is going to have to perform three main tasks:
- Retrieve the process name: this is important because we want the driver to only trace operations for a single process. PID is not a handy option since you only have that once the process has already started. The process name will be checked against a hardcoded string for now, but this could be configurable.
- Retrieve the target file path: So that we can present that to the user.
- Filter output and retrieve request parameters: we are not interested in the process opening every single folder leading up to the target file, and we would like to know the privileges requested for a specific file, and whether the request was successful or not.
For reference, the prototype of a post-operation callback is

```c
FLT_POSTOP_CALLBACK_STATUS TracerCreateLog(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
```

Where `PFLT_CALLBACK_DATA Data` is the only field we will use.

To retrieve the process name we have to take a few steps. On Windows, the thread is the basic "unit" that executes code, not the process, which is just a way to bundle threads together. Along these lines, our callbacks will receive information regarding which thread is carrying out the operation, and we are going to be able to use this to retrieve the process it belongs to thanks to the handy `PsGetThreadProcess` macro, to which we can pass the pointer to the executing thread stored in `Data->Thread` (ATTENTION: this could be NULL so make sure to check!). The macro returns a pointer to the executing process, however, this is still not what we want. We need a handle on the process so that we can eventually call `ZwQueryInformationProcess` on it and get the process name. Fortunately, we can easily get a handle to an object if we have a pointer by using the `ObOpenObjectByPointer` function ([MSDN docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer)). After we get the handle, we can finally call `ZwQueryInformationProcess` after allocating a buffer for the return value. The function can be used to obtain all sorts of information about a process. The `ProcessInformationClass` field can be used as a selector. In our case, we select `ProcessImageFileName` to get the file name of the image for the process.

```c
ULONG size = 1024;
auto processName = (UNICODE_STRING*)ExAllocatePool(PagedPool, size);
if (processName == nullptr) {
    return FLT_POSTOP_FINISHED_PROCESSING;
}
RtlZeroMemory(processName, size);

status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, processName, size - sizeof(WCHAR), nullptr);
if (!NT_SUCCESS(status) || (processName->Length < 0)) {
    ExFreePool(processName);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
```

If the returned buffer does not contain our process name (notepad.exe in our case), we quit processing.

```c
if (wcsstr(processName->Buffer, L"notepad.exe") == nullptr) {
    ExFreePool(processName);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
```

Now that we know that we are intercepting a request from a process we are interested in, we need to find the file name the process is trying to interact with. This is going to be stored in a struct called `FLT_FILE_NAME_INFORMATION` 

```c
typedef struct _FLT_FILE_NAME_INFORMATION {
  USHORT                     Size;
  FLT_FILE_NAME_PARSED_FLAGS NamesParsed;
  FLT_FILE_NAME_OPTIONS      Format;
  UNICODE_STRING             Name;
  UNICODE_STRING             Volume;
  UNICODE_STRING             Share;
  UNICODE_STRING             Extension;
  UNICODE_STRING             Stream;
  UNICODE_STRING             FinalComponent;
  UNICODE_STRING             ParentDir;
} FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;
```

The struct can be retrieved with the API function `FltGetFileNameInformation` for which the prototype is 

```c
NTSTATUS FLTAPI FltGetFileNameInformation(
  [in]  PFLT_CALLBACK_DATA         CallbackData,
  [in]  FLT_FILE_NAME_OPTIONS      NameOptions,
  [out] PFLT_FILE_NAME_INFORMATION *FileNameInformation
);
```

where `CallbackData` is the `Data` parameter passed to our post- callback, `NameOptions` is going to be a constant `FLT_FILE_NAME_NORMALIZED`, and `FileNameInformation` is a pointer that will hold the return `FLT_FILE_NAME_INFORMATION`. The pointer returned in `FileNameInformation`, however, will need to be parsed for all the fields in the struct to be available. This can be done with `FltParseFileNameInformation` ([MSDN docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltparsefilenameinformation)).

```c
FLT_FILE_NAME_OPTIONS nameOptions = FLT_FILE_NAME_NORMALIZED;
PFLT_FILE_NAME_INFORMATION fileNameInformation = nullptr;
status = FltGetFileNameInformation(Data, nameOptions, &fileNameInformation);
if (!NT_SUCCESS(status)) {
    return FLT_POSTOP_FINISHED_PROCESSING;
}
status = FltParseFileNameInformation(fileNameInformation);
if (!NT_SUCCESS(status)) {
    return FLT_POSTOP_FINISHED_PROCESSING;
}
```

With this out of the way, the full file name is going to be available in `fileNameInformation->Name`. We now only need to find whether the process requested read, write, or execute access and whether the request was successful. The requested accesses can be found in `Data->Iopb->Parameters.Create.SecurityContext`, and the request status is going to be located in `Data->IoStatus.Status`. We also want to exclude requests for directories, this can be achieved by excluding files with no extension (this is obviously not a great approach, but it works for a first draft). 

```c
const auto& createParams = Data->Iopb->Parameters.Create;
auto success = NT_SUCCESS(Data->IoStatus.Status);
auto isDirectory = fileNameInformation->Extension.Length == 0;
if (success) {
    if (!isDirectory) {
        bool readAccess = createParams.SecurityContext->DesiredAccess & FILE_READ_DATA;
        bool writeAccess = createParams.SecurityContext->DesiredAccess & FILE_WRITE_DATA;
        bool executeAccess = createParams.SecurityContext->DesiredAccess & FILE_EXECUTE;
        bool success = NT_SUCCESS(Data->IoStatus.Status);
        KdPrint(("'%wZ', Read: %s Write: %s Execute: %s Success: %s", fileNameInformation->Name, readAccess ? "true" : "false", writeAccess ? "true" : "false", executeAccess ? "true" : "false", success ? "true" : "false"));
    }
}
else {
    KdPrint(("Process failed to open a handle to '%wZ'", fileNameInformation->Name));
}
```

With the code all wrapped up, we now just need to write a proper INF file to install the driver. I am not going to go over the who file, just mention a few important places that need attention. For the rest, you can check out the full INF file on my Github.

In the "Version" section I chose "AntiVirus" class and its relative "ClassGuid". You should select the appropriate one from [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/file-system-filter-driver-classes-and-class-guids).

```ini
[Version]
Signature="$WINDOWS NT$"
Class = AntiVirus
ClassGuid = {b1d1a169-c54f-4379-81db-bee7d88d7454}
Provider=%ManufacturerName%
DriverVer=
CatalogFile=TracingDriver.cat
PnpLockdown=1
```

As per the "Strings" section, basically, all needs to be changed to fit your project context. The altitude is related to the "Class" you picked previously. So "329995" belongs to the altitude range of the "AntiVirus" class. You should choose an altitude that fits your class choice. Have a look [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers). The higher the altitude, the higher the mini-filter will be placed on the mini-filter stack.

```ini
[Strings]
ManufacturerName="Giacomo Casoni"
ServiceDescription      = "Actions Tracing Driver"
ServiceName             = "TracingDriver"
DriverName              = "TracingDriver"
DiskId1                 = "TracingDriver Device Installation Disk"
DefaultInstance         = "TracingDriver Instance"
Instance1.Name          = "TracingDriver Instance"
Instance1.Altitude       = "329995"
Instance1.Flags         = 0x0              ; Allow all attachments
```

Once the INF file is ready, right-click on it, hit "Install", then open a Command Prompt as Administrator and load your filter with `fltmc load <your_filter_name>`. Enjoy your all-powerful kernel driver!

<a href="/assets/images/kernelDevelopement/FileTracingDriver.png"><img src="/assets/images/kernelDevelopement/FileTracingDriver.png" margin="0 250px 0" width="100%"/></a>