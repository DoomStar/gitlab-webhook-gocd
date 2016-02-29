**Git Hook Event**

Listens for http requests from GitLab and passes it to GO.CD.

*Add a web hook into gitlab.*
Parameters
- pipeline: pipeline name
- material: material name, equals to git url by default - you should change it to simple string in pipeline settings
- gocd_profile: profile in config name
- gocd_{user|pass|host|port}: set it instead of gocd_profile if you dont want to write it to config file

example1:
http://buildsrv.nct:8001/tag/?pipeline=test&material=git_test&gocd_profile=profile1
example2:
http://buildsrv.nct:8001/tag/?pipeline=test&material=git_test&gocd_user=all&gocd_pass=all&gocd_host=buildsrv.nct&gocd_port=8153

*INSTALLING*

cd /opt
git clone https://gitlab.nct/System/Git_Hook_Event.git
cd Git_Hook_Event
ln -s /opt/Git_Hook_Event/init.sh /etc/init.d/Git_Hook_Event
vi /opt/Git_Hook_Event/githookevent.conf.json
service Git_Hook_Event start