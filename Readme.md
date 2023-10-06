# Diff notes for codefactory-gc-workstation3

## code:
- git clone https://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@github.com/Deloitte/AICOE-Platform-Infrastructure.git -b dev

## diff notes:
- changes in codefactory-gc-workstation3 instance that deployed successfully were compared with original dev branch code
- *note - comparison was done using this VSCode extension in order to enable comparing folders: https://marketplace.visualstudio.com/items?itemName=moshfeu.compare-folders&ssr=false#qna
![](readme1.png)

## changes untracked in this repo:
1. global VSCode search and replace done to change AWS Region to us-gov-west-1
   1. search: "arn:aws" | replace: "arn:aws-us-gov-west-1"
   2. change region to “us-gov-west-1” in terraform-infrastructure/terraform.tf and terraform-infrastructure/variables.tf
2. [profile_onboarding_old.yaml](ansible/profile_onboarding_old.yaml) replaced profile_onboarding.yaml in init.yaml
3. venv folder added to AICOE-Platform-Infrastructure root dir
4. "url: https://github.com/Deloitte/aicoe-tap-gitops.git" changed from "../AICOE-Platform-Gitops.git" in ansible/templates/argocd_token.yaml and ansible/argocd.yaml files

## changes tracked in this repo:
1. [main.tf](terraform-infrastructure/modules/eks/main.tf) - this file reflects all the changes from Natascha that fixed the extra set of node-groups that was unwanted
2. included for reference:
   - [trust.json](ansible/files/trust.json)
   - hardcoded value in [profile.yaml](ansible/templates/profile.yaml)
   - [parameters.tfvars](terraform-infrastructure/parameters.tfvars)
3. DIFFERENCES: the only file with really major changes present in this repo is [cni.yaml](ansible/files/cni.yaml) (notes in the file are included with ##$ tag)
4. NEW FILES:
    - [ansible/templates/centraldashboard-data.yaml](ansible/templates/centraldashboard-data.yaml) 
    - [ansible/templates/dexistio-data.yaml](ansible/templates/dexistio-data.yaml) 
    - [ansible/templates/oidcauthservice-data.yaml](ansible/templates/oidcauthservice-data.yaml)
    - [ansible/create_collaborators.yaml](ansible/create_collaborators.yaml) 
    - [ansible/create_profile_policy_role.yaml](ansible/create_profile_policy_role.yaml) 
    - [ansible/create_profiles.yaml](ansible/create_profiles.yaml) 
    - [ansible/profile_onboarding_old.yaml](ansible/profile_onboarding_old.yaml)

## helpful CL commands:
#### Workstation
- ```ansible-playbook init.yaml --extra-vars include_iam_s3=false  --skip-tags kubeconfig,helm,cni,eni,alb,autoscaler```
#### Bastion
- ArgoCD admin password
  - ```kubectl -n argocd get secret argocd-initial-admin-secret  -o jsonpath="{.data.password}" | base64 -d```

## contacts
1. GovCloud request contacts (specifically infrastructure creation request):
   - Syed, Nizam <nsyed@deloitte.com>
   - Tant, Tommy <jtant@deloitte.com>
   - Colburn, Rob <rcolburn@deloitte.com>
   - Tolliver, Andy <atolliver@deloitte.com>
2. Technical Account Managers for AWS
   - AWS TAM for Deloitte at aws-tam-deloitte@amazon.com
     - Robenalt, John <jrobenal@amazon.com> - Sales
     - Govindankutty, Sunil <govisun@amazon.com> - Prod Support
     - Manoj Rajan <mrmanoj@amazon.com> - Prod Support
     - Paolo Barone <paobar@amazon.com>