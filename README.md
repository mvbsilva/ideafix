# IDEAFIX

IDEAFIX present the first approach to identify elephant flows in Internet eXchange Points (IXPs) faster by relying in programmable data planes.
IDEAFIX takes advantage of P4 features (https://github.com/p4lang) to store and analyze the information about the size and duration of the flows entirely in the data plane.
The entire IDEAFIX description and results are presented in the paper: https://doi.org/10.1109/GLOCOM.2018.8647685.


In a second adaptation, we extended the application of IDEAFIX to use dynamic thresholds. Our mechanism uses the information reported by the data plane to monitor network utilization in the control plane and to calculate local classification threshold values. Thus, the identification thresholds on the switches are updated by the controller to make the identification process more in tune with the network behavior. The entire description and results are compiled in a paper (in progress).

This repository contains the scripts used in the prototype and experimental evaluation, as described below:<br/>
`ideafix.p4`          - Programmable P4_16 Switch to identify elephant flows in the data planes. <br/>
* receive.py          - Switch-controller communication interface.<br/>
* controller.py       - SDN-Controller and traffic manager for IXP network.<br/>
* p4app.json          - Pointer for P4 application and topology.<br/>
* topology_net        - Mapping the infrastructure to the controller.<br/>
* updateThreshold.py  - P4 CLI configuration and update thresholds.<br/>
* startFlows.py       - Workload generator by Iperf3.<br/>


For execution:<br/>
- After installing P4 environment (https://github.com/p4lang)<br/>

1. Start P4 topology mininet:
```
bash ./run.sh
```

2. Start Controller/Sniffer
```
python receive.py
```

3. Start Workload
```
python stratFlows.py
```



Marcus Vinicius Brito da Silva<br/>
mvbsilva@inf.ufrgs.br<br/>
Computer Science PhD student<br/>
Federal University of Rio Grande do Sul (UFRGS)<br/>
Porto Alegre, Brazil.
