## ARM (Azure Resource Manager):
To keep it short, an ARM template is a JSON file that defines the infrastructure and config for your resources. I.e., IaaS (Infrastructure as Code) for Azure.
If you would like to read more documentation consider checking out [What is Azure Resource Manager? by Microsoft](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview)

I will jump right into how to generate your own ARM template from your lab:
1. Go to the Resource Group that contains your lab.
2. Click "Automation" dropdown tab, followed by "Export Template"
3. Azure will generate a full `azuredeploy.json` file based on your current setup. (note: this may take some time*)
4. From here you can click download and redeploy your Resource Group!
