/system scheduler
add interval=5m name=IPSec-bruteforce-ban policy=read,write,policy,test start-date=jan/01/2020 start-time=\
    00:00:01 on-event=":\
    local logMessage \"\"\r\
    \n:local logIp \"\"\r\
    \n/log\r\
    \n:foreach i in=[find where message~\"phase1 negotiation failed\\\\.\" or \
    message~\"SPI.*not regist\" or message~\"Invalid exchange\" ] do={\r\
    \n    :set logMessage [get \$i message]\r\
    \n\r\
    \n    :if ((\$logMessage~\"phase1 negotiation failed\\\\.\") && ([:find \$\
    logMessage \"script\"] <1)) do={\r\
    \n        :set logIp [:toip [:pick \$logMessage -1 [:find \$logMessage \" \
    \"]]]\r\
    \n        :if ([:typeof \$logIp] = \"ip\") do={\r\
    \n            :if ([:len [/ip fire addr find where list=IPSEC address=\$lo\
    gIp]] < 1) do={\r\
    \n                /ip fire addr add address=\$logIp list=IPSEC timeout=7d\
    \r\
    \n                :log info message=\"script=IPSEC_failed src_ip=\$logIp w\
    hy=negotiation_failed\"\r\
    \n            }\r\
    \n        }\r\
    \n    }\r\
    \n\r\
    \n    :if ((\$logMessage~\"SPI .* not registered for\") && ([:find \$logMe\
    ssage \"script\"] <1)) do={\r\
    \n        :set logIp [:toip [:pick \$logMessage ([:find \$logMessage \"for\
    \_\"]+4) [:find \$logMessage \"[\"]]]\r\
    \n        :if ([:typeof \$logIp] = \"ip\") do={\r\
    \n            :if ([:len [/ip fire addr find where list=IPSEC address=\$lo\
    gIp]] < 1) do={\r\
    \n                /ip fire addr add address=\$logIp list=IPSEC timeout=7d\
    \r\
    \n                :log info message=\"script=IPSEC_failed src_ip=\$logIp w\
    hy=SPI_not_registered\"\r\
    \n            }\r\
    \n        }\r\
    \n    }\r\
    \n\r\
    \n    :if ((\$logMessage~\"Invalid exchange\") && ([:find \$logMessage \"s\
    cript\"] <1)) do={\r\
    \n        :set logIp [:toip [:pick \$logMessage ([:find \$logMessage \"for\
    \_\"]+4) [:find \$logMessage \"[\"]]]\r\
    \n        :if ([:typeof \$logIp] = \"ip\") do={\r\
    \n            :if ([:len [/ip fire addr find where list=IPSEC address=\$lo\
    gIp]] < 1) do={\r\
    \n                /ip fire addr add address=\$logIp list=IPSEC timeout=7d\
    \r\
    \n                :log info message=\"script=IPSEC_failed src_ip=\$logIp w\
    hy=Invalid_exchange\"\r\
    \n            }\r\
    \n        }\r\
    \n    }\r\
    \n}\r\
    \n"
