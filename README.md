# pcsetup

I work at an MSP so I have to run setup on a lot of computers. Of the 22 steps we have documented for PC setup, this automates 12 of them.

Things this script does:
1. Registers Powershell Gallery as a trusted Powershell Module Source
2. Installs the Dell BIOS Provider PS Module
3. Configures BIOS Power Settings
    - AC Power Recovery: Last State
    - Deep Sleep: Disabled
    - Block Sleep: Enabled
4. Sets Serial Number as PC Name
5. Sets Windows Power Settings
    - Turns on High Performance mode
    - Disables Hibernation service
6. Sets Timezone to Eastern Standard Time
7. Runs [Decrapinator](https://github.com/sthurston99/Decrapinator) to clear out junk programs
8. Installs Winget Package Manager
9. Installs default programs via Winget
    - Google Chrome
    - Adobe Acrobat Reader
    - Microsoft Office (Using my [default config](https://github.com/sthurston99/dotfiles/blob/main/.odt.xml))
10. Runs Dell Command Update
11. Reboots the computer

Obviously this won't fully work on non-dell computers. And since it uses Decrapinator over the website, the uninstalls are limited to what that is able to handle. Current goals for updating are:

- Fix the issues with Decrapinator to improve uninstall flow
- Debug issues with wait times between commands to improve reliability
- Fix other nonworking parts as they come up