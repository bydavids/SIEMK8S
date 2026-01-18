FROM grafana/grafana:latest

RUN grafana-cli plugins install marcusolsson-json-datasource

COPY provisioning /etc/grafana/provisioning
COPY dashboards /var/lib/grafana/dashboards

EXPOSE 3000
