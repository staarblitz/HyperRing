> [!WARNING]
> HyperRing is WIP and is extremely unstable. There is no API, neither a SDK developers use. The source code is published solely for inspection purposes.


# HyperRing - Expose your kernel like you mean it.
HyperRing is a hypervisor designed to monitor the kernel and user-mode programs, and allow access to kernel mode via hyper_ring_sdk from user-mode.

## Technical Details
### Features
#### 1. Exposes kernel-mode API to user-mode.
HyperRing allows user-mode applications (so called _HyperPlugins_) to use kernel-mode and hypervisor-specific APIs. Some examples are:
- Allocating physical memory
- Mapping physical memory
- Benefitting from opaque kernel structures (like `EPROCESS` and `ETHREAD`)
- Real-time notifications (like exceptions, interrupts and so on)
- And many more!
#### 2. Easy interfacing
HyperRing is interfaced through `VMCALL`s to make it easier for software to utilize HyperRing SDK.
#### 3. Security
Yeah, the term "security" and "expose" doesn't come together so easily. That is why HyperRing is built with a plugin-like system with authorization.
Each _HyperPlugin_ that wants to do specific thing (like allocating memory, terminating a process) must authenticate itself with those access masks, then issue a `VMCALL`. The end-user receives an UAC like prompt to choose whether or not to allow this application. If user trusts the plugin, he may choose to "always allow". Which plugins are kept by their file signatures and file names.

### How Does It Work?
HyperRing is a hypervisor, running on top of the kernel and user-mode, but below System Management Mode (SMM), allowing it to be utilized both from kernel and user-mode.
HyperRİng virtualizes each core on the system as described on Intel's Software Developer Manual. Adjusting and isolating them from HyperRing, and hides its presence until asked (e.g. `VMCALL`).

## End Goal
Windows is a great OS. No doubts in it. But its precious kernel has so many parts hidden and private, with lack of standardization among people who wants to extend it. HyperRing comes as a rescue for this.
With HyperRing, you can easily:
- Write antivirus software to monitor your computer
- Isolate each process on the system
- Write your own plugins in your favourite language (C#, C, Rust...)
- And share them with other people!

Nothing like having control over your own operating system, right?

## Support
HyperRing is Work in Progress (WIP) and currently the hypervisor module is being developed.
You might want to donate, or contact me and provide support at Telegram to resolve issues around HyperRing.

## Known Issues
1. `iretq` at `KiInterruptDispatchNoLockNoEtw` throws a `#GP`. The stack is garbaged. Thus, the system crashes before a complete virtualization.
