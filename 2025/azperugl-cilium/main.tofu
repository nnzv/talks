/// Global Azure 2025
///
/// This configuration provisions an Azure Kubernetes Service (AKS) cluster using OpenTofu
/// and the `azurerm` provider. It includes a basic networking setup with overlay mode via
/// Cilium. The cluster uses AzureLinux nodes, a basic load balancer, and minimal drivers
/// for a lean profile.
///
/// Before applying, ensure the `KubeletDisk` feature is enabled in your subscription:
///
///     az feature register --namespace "Microsoft.ContainerService" --name "KubeletDisk"
///
/// Set the following environment variables with your Azure credentials:
///
///     export ARM_SUBSCRIPTION_ID="..."
///     export ARM_TENANT_ID="..."
///
/// Initialize and apply the configuration:
///
///     tofu init
///     tofu apply -auto-approve

locals {
  suffix   = "azperugl"
  location = "East US"
}

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.26.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg" {
  name     = "rg${local.suffix}01"
  location = local.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = "vnet${local.suffix}01"
  address_space       = ["10.100.0.0/27"]
  location            = local.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "snet" {
  name                 = "snet${local.suffix}01"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.100.0.0/28"]
}

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "aks${local.suffix}01"
  kubernetes_version  = "1.32.3" # https://releases.aks.azure.com
  location            = local.location
  resource_group_name = azurerm_resource_group.rg.name
  node_resource_group = "rg${local.suffix}02"
  dns_prefix          = "aks${local.suffix}01"
  run_command_enabled = false
  default_node_pool {
    name                 = "np${local.suffix}01"
    node_count           = 1
    os_sku               = "AzureLinux"
    vm_size              = "Standard_D2s_v3"
    vnet_subnet_id       = azurerm_subnet.snet.id
    kubelet_disk_type    = "Temporary"
    auto_scaling_enabled = false
  }
  identity {
    type = "SystemAssigned"
  }
  storage_profile {
    disk_driver_enabled = false
    file_driver_enabled = false
    blob_driver_enabled = false
    snapshot_controller_enabled = false
  }
  network_profile {
    network_plugin      = "azure"
    network_data_plane  = "cilium"
    network_plugin_mode = "overlay"
    network_policy      = "cilium"
    pod_cidr            = "192.168.0.0/27"
    service_cidr        = "172.16.0.0/27"
    dns_service_ip      = "172.16.0.10"
    load_balancer_sku   = "basic"
  }
}
