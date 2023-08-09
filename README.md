# OPC-UA Exploitation Framework / by Claroty Team82

### TL;DR
Advanced OPC-UA framework for vulnerability research & exploitation. 

Using this framework, we've implemented many unique attacks against OPC-UA implementation - all of which we, or other researchers, responsibly disclosed. So far, using `OPC-UA Exploitation Framework` we found & disclosed ~50 CVEs.

### Background
In the past few years we ([Claroty Research - Team82](https://claroty.com/team82)) conducted an extensive analysis of the [OPC-UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) network protocol prevalent in operational technology (OT) networks worldwide. During that research, we found and privately disclosed critical vulnerabilities in OPC-UA implementations from a number of leading vendors that have built their respective products on top of the protocol stack. The affected vendors sell these products to companies operating in many industries within the ICS domain and so with each vulnerability found in a protocol-stack library there are many other pieces of software and applications that are becoming vulnerable.

With our `OPC-UA Exploitation Framework` we hope that both software companies and OPC-UA vendors could test their code-base and improve the security of their products. We also welcome other security researchers to use this framework and responsibly disclose vulns/bugs they find to the respective vendors.

We used this framework many times, including:
- [Pwn2Own ICS 2020](https://www.zerodayinitiative.com/blog/2019/10/28/pwn2own-miami-bringing-ics-into-the-pwn2own-world)
- [Pwn2Own ICS 2022](https://www.zerodayinitiative.com/blog/2021/10/22/our-ics-themed-pwn2own-contest-returns-to-miami-in-2022)
- [Pwn2Own ICS 2023](https://www.zerodayinitiative.com/blog/2022/11/30/pwn2own-returns-to-miami-beach-for-2023)

As part of our research we also wrote a detailed series into OPC-UA - [OPC UA Deep Dive: A Complete Guide to the OPC UA Attack Surface](https://claroty.com/team82/research/opc-ua-deep-dive-a-complete-guide-to-the-opc-ua-attack-surface) and even released an [OPC-UA Network Fuzzer](https://claroty.com/team82/research/team82-releases-homegrown-opc-ua-network-fuzzer-based-on-boofuzz)

### What's supported?
We divided the framework to four categories: `attacks`, `corpus`, `sanity`, and `server`
- `Sanity`: sanity payloads such as reading nodes, getting specific NodeID information given a namespace and NodeID, etc.
- `Attacks`: unique OPC-UA specific attacks that can cause a denial of service, leak sensitive information, or even execute code remotely.
- `Corpus`: reproducing payloads from corpus. Useful for fuzzing iterations and reproducers.
- `Server`: Simple server implementation (currently one example with XSS payloads).

### Command Line
Basic Usage: `python main.py SERVER_TYPE IP_ADDR PORT ENDPOINT_ADDRESS FUNC_TYPE [DIR]`
Examples:
1. Sanity - `python main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer sanity`
2. Attack (DoS) - `python main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer thread_pool_wait_starvation`
3. `python main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer opcua_file FILE_PATH NUM_REQUESTS`
4. `python main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer opcua_dir PATH_TO_DIR_WITH_CORPUS`
5. `python main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer boofuzz_db BOOFUZZ_DB_FILEPATH`
6. `python main.py prosys 1.2.3.4 53530 /OPCUA/SimulationServer threads_run FUNC_NAME COUNT`
 
- Server Types: `softing`, `unified`, `prosys`, `kepware`, `triangle`, `dotnetstd`, `open62541`, `ignition`, `rust`,  `node-opcua`, `opcua-python`, `milo`, `s2opc`
- Function types: `threads_run`, `sanity `, `sanity_read_nodes `, `sanity_translate_browse_path `, `sanity_read_diag_info `, `sanity_get_node_id_info `, `opcua_dir `, `opcua_file `, `boofuzz_db `, `attack_file_nodejs_opcua_v8_oom `, `attack_file_ASNeG_OpcUaStack_unhandled_exception `, `chunk_flood `, `open_multiple_secure_channels `, `close_session_with_old_timestamp `, `complex_nested_message `, `translate_browse_path_call_stack_overflow `, `thread_pool_wait_starvation `, `unlimited_persistent_subscriptions `, `function_call_null_deref `, `malformed_utf8 `, `race_change_and_browse_address_space `, `certificate_inf_chain_loop `, `unlimited_condition_refresh`

### Sanity
| Sanity Name                     | Description | Function Keyword | Reference |
|---------------------------------|---|---|---|
| Diagnostic Info | Diagnostic summary information for the Server | `sanity_read_diag_info`  | [Server Diagnostics Summary Data](https://reference.opcfoundation.org/v104/Core/docs/Part5/12.9)  |
| Get Node ID Info | Node ID is an identifier for a node in an OPC server’s address space. | `sanity_get_node_id_info`  | [NodeID](https://documentation.unified-automation.com/uasdkhp/1.4.1/html/_l2_ua_node_ids.html)  |
| Read Nodes | Read service is used to read attributes Nodes | `sanity_read_nodes`  | [Read Service](https://reference.opcfoundation.org/v105/Core/docs/Part4/5.10.2/)  |
| Translate Browse Path | Translates browse paths to NodeIds. Each browse path is constructed of a starting Node and a RelativePath | `sanity_translate_browse_path`  | [Translate Browse Path Service](https://reference.opcfoundation.org/Core/Part4/v104/docs/5.8.4)  |

### Unique Attacks
| Attack Name                               | Description | Vulnerability Type    | Function Keyword  | CVE and Reference |
|-------------------------------------------|---|-----------------------|---|---|
| Certificate Infinite Chain Loop           | Some servers implemented the Certificate chain check by themselves and forgot to protect against a chain loop. Example: CertA is signed by CertB which is signed by CertA | Denial of Service     | `certificate_inf_chain_loop`  | [CVE-2022-37013](https://sector7.computest.nl/post/2022-09-unified-automation-opcua-cpp/)  |
| Chunk Flooding                            | Sending huge amount of chunks without the Final chunk  | Denial of Service     |  `chunk_flood` | [CVE-2022-29864](https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2022-29864.pdf), [CVE-2022-21208](https://security.snyk.io/vuln/SNYK-JS-NODEOPCUA-2988723), [CVE-2022-25761](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25761), [CVE-2022-25304](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25304), [CVE-2022-24381](https://security.snyk.io/vuln/SNYK-UNMANAGED-ASNEGOPCUASTACK-2988735), [CVE-2022-25888](https://security.snyk.io/vuln/SNYK-RUST-OPCUA-2988751) | 
| Open Multiple Secure Channels             | Flooding the server with many open channel requests leads to a denial of service | Denial of Service  | `open_multiple_secure_channels`  | [CVE-2023-32787](https://nvd.nist.gov/vuln/detail/CVE-2023-32787)  |
| Close Session With Old Timestamp          | Sending bad timestamp on closing session leads to an uncaught stacktrace with sensitive information  | Information Leakage   | `close_session_with_old_timestamp`  | [CVE-2023-31048](https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2023-31048.pdf)  |
| Complex Nested Message                    | Sending a complex nested variant leads to a call stack overflow  | Denial of Service / Information Leakage  | `complex_nested_message`  |  [CVE-2022-25903](https://security.snyk.io/vuln/SNYK-RUST-OPCUA-2988750), [CVE-2021-27432](https://nvd.nist.gov/vuln/detail/CVE-2021-27432), [CVE-2023-3825](https://www.cisa.gov/news-events/ics-advisories/icsa-23-208-02)|
| Translate Browse Path Call Stack Overflow | Triggering a stack overflow exception in a server that doesn't limit TranslateBrowsePath resolving calls | Denial of Service     | `translate_browse_path_call_stack`  | [CVE-2022-29866](https://jfrog.com/blog/crashing-industrial-control-systems-at-pwn2own-miami-2022/)  |
| Thread Pool Wait Starvation               | Thread pool deadlock due to concurrent worker starvation  | Denial of Service     | `thread_pool_wait_starvation`  | [CVE-2022-30551](https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2022-30551.pdf)  |
| Unlimited Persistent Subscriptions        | Flooding the server with many monitored items with 'delete' flag set to False leads to uncontrolled memory allocation and eventually to a denial of service  | Denial of Service     | `unlimited_persistent_subscriptions`  | [CVE-2022-25897](https://security.snyk.io/vuln/SNYK-JAVA-ORGECLIPSEMILO-2990191),[CVE-2022-24375](https://security.snyk.io/vuln/SNYK-JS-NODEOPCUA-2988725),[CVE-2022-24298](https://security.snyk.io/vuln/SNYK-UNMANAGED-FREEOPCUAFREEOPCUA-2988720)  |
| Function Call Null Dereference            | Triggering an application crash after several OPC UA methods have been called and the OPC UA session is closed before the methods have been finished.  | Denial of Service     | `function_call_null_deref` |  [CVE-2022-1748](https://nvd.nist.gov/vuln/detail/CVE-2022-1748) |
| Malformed UTF8                            | Triggering an application crash after processing malformed UTF8 strings  | Remote Code Execution | `malformed_utf8`  |  [CVE-2022-2825](https://nvd.nist.gov/vuln/detail/CVE-2022-2825), [CVE-2022-2848](https://nvd.nist.gov/vuln/detail/CVE-2022-2848) |
| Race Change And Browse Address Space      | Adding nodes to the server address space and removing the nodes in a loop while browsing the entire address space.  | Denial of Service     | `race_change_and_browse_address_space`  | [CVE-2023-32172](https://www.zerodayinitiative.com/advisories/ZDI-23-777/)  |
| Unlimited Condition Refresh               | Sending many ConditionRefresh method calls leads to uncontrolled memory allocations and eventually to a crash | Denial of Service     | `unlimited_condition_refresh`  | [CVE-2023-27321](https://files.opcfoundation.org/SecurityBulletins/OPC%20Foundation%20Security%20Bulletin%20CVE-2023-27321.pdf), [CVE-2023-27334](https://industrial.softing.com/fileadmin/psirt/downloads/syt-2023-1.html) [CVE-2023-39477](https://www.zerodayinitiative.com/advisories/ZDI-23-1050/)|




### Corpus Attacks
We've implemented a couple of corpus usage attacks, mostly to reproduce bugs we found using fuzzers.
- `opcua_message_boofuzz_db` - can be used to shoot an entire boofuzz db at a target
- `opcua_message_file` - can be used to shoot an a single file or directory of files with OPC-UA payloads (OPC-UA content itself)

Take a look at the corpus we have collected - `input_corpus_minimized`. They are the result of many hours of fuzzing different targets via various methods and tools.

### Rogue Server Implementation (to attack clients)
Currently, the server is a stand-alone script which is built on top of Python OPC-UA ([asyncua](https://github.com/FreeOpcUa/opcua-asyncio)). The current example was used in some RCE client exploitation (for example see [here](https://security.inductiveautomation.com/?tcuUid=379811a7-c116-4855-b1ce-a2b2d828b5ef)).

### Supported OPC-UA Servers
| Server Name                                                                                                                                                  | Default URI  | Default Port  | Server Keyword  |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------|---|---|---|
| [PTC Kepware KepServerEx](https://www.ptc.com/en/products/kepware/kepserverex)                                                                               |  `/` | 49320  |  `kepware` |
| [OPC UA .NET Standard Protocol Stack](https://github.com/OPCFoundation/UA-.NETStandard)                                                                      | `/Quickstarts/ReferenceServer` | 62541  |  `dotnetstd` |
| [OPC UA Secure Integration Server](https://industrial.softing.com/products/opc-opc-ua-software-platform/integration-platform/secure-integration-server.html) | `/Softing/dataFEED/Server` | 4897  | `softing`  |
| [Prosys OPC UA Simulation Server](https://prosysopc.com/products/opc-ua-simulation-server)                                                                   | `/OPCUA/SimulationServer`  | 53530  | `prosys`  |
| [Unified Automation UaGateway ](https://www.unified-automation.com/products/ua-runtime-software/uagateway.html)                                              |  `/` | 48050  | `unified` |
| [Inductive Automation Ignition](https://inductiveautomation.com/)                                                                                            | `/`  | 62541  | `ignition`  |
| [Triangle Microworks Scada Data Gateway (SDG)](https://www.trianglemicroworks.com/products/scada-data-gateway/overview)                                      |  `/SDG` | 4885  | `triangle`  |
| [open62541 OPC-UA Protocol Stack](https://github.com/open62541/open62541/)                                                                                   | `/`  |  4840 | `open62541`  |
| [Locka99 OPC-UA Protocol Stack](https://github.com/locka99/opcua/)                                                                                           | `/`  | 4855  | `rust`  |
| [Node OPC-UA Protocol Stack](https://github.com/node-opcua/node-opcua)                                                                                       | `/`  | 26543  | `node-opcua`  |
| [Python OPC-UA Protocol Stack](https://github.com/FreeOpcUa/opcua-asyncio)                                                                                   |`/freeopcua/server/`  | 4840  | `opcua-python`  |
| [Milo OPC-UA Protocol Stack](https://github.com/eclipse/milo)                                                                                                | `/milo`  |  62541 | `milo`  |
| [S2OPC OPC-UA Protocol Stack](https://gitlab.com/systerel/S2OPC)                                                                                                | `/`  |  4841 | `s2opc`  |

### How to use
```
git clone https://github.com/claroty/opcua-exploit-framework.git
cd opcua-exploit-framework
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```
then for example, `python main.py ignition 10.10.6.40 62541 "" sanity`
do `python main.py -h` for help

### Credits
The framework was mainly developed by [Claroty Research - Team82](https://claroty.com/team82/) including:
- Vera Mens
- Uri Katz
- Noam Moshe
- Sharon Brizinov
- Amir Preminger

Some of the implemented attacks are based on vulnerabilities and/or research conducted by other researchers including [JFrog](https://jfrog.com/), [Computest Sector7](https://sector7.computest.nl/), [OTORIO](https://www.otorio.com), and others.

