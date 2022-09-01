# antiVM  ida pro plugin

## Description
The antiVM aims to quickly identify anti-virtual machine and anti-sandbox behavior. This can speed up malware analysis.

This antiVM.rules is based on an extension of [here](https://github.com/Yara-Rules). Then, using the [al-khaser](https://github.com/LordNoteworthy/al-khaser) to test and enrich the rules.

Unfortunately, the al-khaser don not provide release any more. You can find the in this repo.

# How to use

Just put the antiVM.py and antiVM.rules in your ida7.x  plugins directory and here we go.

Before using the plugin you must install the python Yara module:`pip install yara-python`

The plugin can be launched from the menu using `Edit->Plugins->antiVM` or using `Ctrl-Alt-A` 
![show](https://github.com/Hipepper/antiVM/raw/main/png/show.gif)

# some todo 

some yara rules are broad like this one. This may bring some false positives.
```
rule sandBox_usernames {
    meta:
        Author = "jentle"
        reference = "https://www.sentinelone.com/blog/gootkit-banking-trojan-deep-dive-anti-analysis-features/"

    strings:
        $s1="CurrentUser" wide
		$s2="Sandbox" wide
		$s3="Emily" wide
		$s4="HAPUBWS" wide
		$s5="Hong Lee" wide
		$s6="IT-ADMIN" wide
		$s7="milozs" wide
		$s8="Peter Wilson" wide
		$s9="timmy" wide
		$s10="user" wide
		$s11="sand box" wide
		$s12="malware" wide
		$s13="maltest" wide
		$s14="test user" wide
		$s15="virus" wide
    condition:
        any of them
}
```

So some malicious behavior rules will be expanded in the future. And more IOA need to be collected.
