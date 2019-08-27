# Description
This repository is part of the MISP-dockerized environment. The Project is hosted on github: https://github.com/DCSO/MISP-dockerized.

# Documentation
The MISP dockerized Test Bench is used to test the complete MISP-dockerized environment after build. A description of the process and the tests itself can be found in the official MISP-dockerized documentation, which is available at https://dcso.github.io/MISP-dockerized-docs/.

# Usage
The Modules of the Test Bench can be called separately to test only specific parts of MISP-Dockerized. To test a single 
module, pass the module in the unittest call:

```bash
python -m unittest misp-testbench.MISPConnection                #to test only the MISPConnection Testcase

python -m unittest misp-testbench.MISPCoreFunctions             #to test only the MISPCoreFunctions Testcase

python -m unittest misp-testbench.MISPEventHandling             #to test only the MISPEventHandling Testcase

python -m unittest misp-testbench.MISPUserManagement            #to test only the MISPUserManagement Testcase

python -m unittest misp-testbench.MISPFeedAndServerHandling     #to test only the MISPFeedAndServerHandling Testcase
```

# License
View [license information](https://github.com/DCSO/MISP-dockerized-server/blob/master/LICENSE) for the software contained in this image.
As with all Docker images, these likely also contain other software which may be under other licenses (such as Bash, etc from the base distribution, along with any direct or indirect dependencies of the primary software being contained).
As for any pre-built image usage, it is the image user's responsibility to ensure that any use of this image complies with any relevant licenses for all software contained within.

# Links
https://github.com/xmlrunner/unittest-xml-reporting