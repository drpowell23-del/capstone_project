# Create Argo CD namespace
resource "kubernetes_namespace_v1" "argocd" {
  metadata {
    name = "argocd"
  }
}

# Deploy Argo CD via Helm
resource "helm_release" "argocd" {
  name       = "argocd"
  namespace  = kubernetes_namespace_v1.argocd.metadata[0].name
  repository = "https://argoproj.github.io/argo-helm"
  chart      = "argo-cd"
  version    = "6.7.18"

  values = [yamlencode({
    server = {
      service = {
        type = "LoadBalancer"
      }
    }
  })]
}

# Read the LoadBalancer Service
data "kubernetes_service_v1" "argocd_server" {
  metadata {
    name      = "argocd-server"
    namespace = kubernetes_namespace_v1.argocd.metadata[0].name
  }

  depends_on = [helm_release.argocd]
}

# Output the URL for the Argo CD Web UI
output "argocd_url" {
  description = "Argo CD Web UI"
  value       = "https://${data.kubernetes_service_v1.argocd_server.status[0].load_balancer[0].ingress[0].hostname}"
}
