# Auth service

#### Clone the repository

```bash
git clone https://github.com/communcom/auth-service.git
cd auth-service
```

#### Create .env file

```bash
cp .env.example .env
```

Add variables
```bash
GLS_CYBERWAY_HTTP_URL=http://cyberway-node
```

#### Create docker-compose file

```bash
cp docker-compose.example.yml docker-compose.yml 
```

#### Run

```bash
docker-compose up -d --build
```