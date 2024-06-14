# Output Formats

methodaws supports several different output formats.

## JSON

Output AWS information in a well structured JSON format that is easily parsed by a variety of data integration tools, allowing you to automate your AWS visibility challenges and leverage methodaws as as sensor.

## Signal

A well structured JSON specification used by the Method Platform, the Signal contains all of the information contained within `content` key of the JSON command as a Base64 encoded string. This is in keeping with the Method Platform [Signal](signal) specification, allowing for non-JSON based cybersecurity tools to be leveraged within Method.

[signal]: https://github.com/Method-Security/pkg/blob/develop/signal/signal.go
