FROM projectdiscovery/nuclei:latest

# Install the official Nuclei templates into the image
RUN nuclei -update-templates

ENTRYPOINT ["nuclei"]