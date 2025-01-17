# Release checklist

* Before release, doublecheck that all issues planned for the current release are either closed or postponed to next 
  milestone (New milestone may need to be eventually created).
* Release can be done by trigger GH workflow (Permissions required)
* After release, it can be good to [close the corresponding milestone](https://github.com/keycloak/keycloak-js/milestones) (permissions required)
* GH workflow needs to be executed in [keycloak-quickstarts](https://github.com/keycloak/keycloak-quickstarts/actions) to 
  update keycloak-client version (TBD as workflow not available yet)
* GH workflow needs to be executed in [keycloak-web](https://github.com/keycloak/keycloak-web/actions)  to update 
  keycloak-client version and send the blog (TBD as workflow not available yet)
  
