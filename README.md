# auth.iudx.org.in

# Pre-requisites
#. If the host OS is not Ubuntu then install the following dependencies manually
> - docker
> - docker-compose

# Setup

```
git clone https://github.com/rbccps-iisc/auth.iudx.org.in
cd auth.iudx.org.in
./setup			# will setup required environment
npm start		# will start auth server in production mode, NOTE: If prompted use sudo
npm test		# will start auth server in development mode, NOTE: If prompted use sudo
```

# For doc creation, run the following commands
```
sudo npm install -g curl-trace-parser --unsafe-perm=true --allow-root
sudo npm install -g aglio --unsafe-perm=true --allow-root
sudo npm install -g apib2swagger --unsafe-perm=true --allow-root

```

# Live
The system will be live at **https://localhost:443**
