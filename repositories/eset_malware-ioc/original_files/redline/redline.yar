// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These YARA rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2024, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule cw_Windows_Redline_panel_tab_headers
{
    meta:
        description = "Matches view headers in Redline Panel"
        author = "ESET Research"
        date = "2022-10-11"
        last_modified = "2024-11-12"
        hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
        reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = 2
    strings:
        $ = "RedLine | Log In"
        $ = "RedLine | Autofilles Viewer"
        $ = "RedLine | Choose Browser"
        $ = "RedLine | Cookie Viewer"
        $ = "RedLine | Credit Card Viewer"
        $ = "RedLine | Files Viewer"
        $ = "RedLine | Log saver"
        $ = "RedLine | System Info Viewer"
    condition:
        uint16(0) == 0x5A4D and 6 of them
}

rule cw_Windows_Redline_panel_distinctive_strings
{
    meta:
        description = "Matches rare strings found in Redline panel"
        author = "ESET Research"
        date = "2022-10-11"
        last_modified = "2024-11-12"
        hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
        reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = 2
    strings:
        $env_var = "%DSK_23%"
        $fn_name = "IsGratherThan"
        $telegram0 = "Telegram: @REDLINESUPPORT"
        $telegram1 = "https://t.me/REDLINESUPPORT"

    condition:
        uint16(0) == 0x5A4D and any of them
}

rule cw_Windows_Redline_panel_prompts
{
    meta:
        description = "Matches prompt messages in Redline panel"
        author = "ESET Research"
        date = "2022-10-11"
        last_modified = "2024-11-12"
        hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
        reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = 2
    strings:
        $ = "Choose directory to save log"
        $ = "Select log to set comment"
        $ = "Please enter an action to create new task"
        $ = "Please enter a target to create new task"
        $ = "Please enter a final point to create new task"
        $ = "Please enter a correct action to create new task"
        $ = "Please enter a correct final point to create new task"
        $ = "Please enter an action to edit task"
        $ = "Please enter a target to edit task"
        $ = "Please enter a final point to edit task"
        $ = "Please enter a correct action to edit task"
        $ = "Please enter a correct final point to edit task"
        $ = "Please enter a correct status to edit task"
        $ = "Please, enter a domains"
        $ = "Please, enter a valid server ip"
        $ = "Choose a file to pump"
        $ = "Enter a valid count of bytes"
        $ = "Enter a valid count of bytes. Must be more then zero"
        $ = "Disconnected. Reboot your panel"
    condition:
        uint16(0) == 0x5A4D and 10 of them
}

rule cw_Windows_Redline_panel_status_message_strings
{
    meta:
        description = "Matches error/success messages in Redline panel"
        author = "ESET Research"
        date = "2022-10-11"
        last_modified = "2024-11-12"
        hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
        reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = 1
    strings:
        $ = "All Browsers are empty"
        $ = "Client [{0}:{1}:{2}] completed task with {3} ID."
        $ = "A List of logs cleared"
        $ = "Browsers not found"
        $ = "Browsers is empty"
        $ = "Done. Check your build file"
        $ = "You must to enable assembly info or certificate in settings"
        $ = "Duplicate log from "
        $ = "Password list is empty"
        $ = "Cookie list is empty"
        $ = "FTPs not found"
        $ = "Files not found"
    condition:
        uint16(0) == 0x5A4D and 8 of them
}

rule cw_Windows_Redline_panel_commands
{
    meta:
        description = "Matches commands and functionalities in Redline panel"
        author = "ESET Research"
        date = "2022-10-11"
        last_modified = "2024-11-12"
        hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
        reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = 2
    strings:
        $cmd0 = "Download"
        $cmd1 = "RunPE"
        $cmd2 = "DownloadAndEx"
        $cmd3 = "OpenLink"
        $cmd4 = "Cmd"
        $action0 = "GrabBrowsers"
        $action1 = "GrabFiles"
        $action2 = "GrabImClients"
        $action3 = "AntiDuplicate"
        $action4 = "grabBrowsers"
        $action5 = "grabFiles"
        $action6 = "grabImClients"
        $action7 = "antiDuplicate"
    condition:
        uint16(0) == 0x5A4D and all of ($cmd*) and 4 of ($action*)
}
