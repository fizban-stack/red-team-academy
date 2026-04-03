pipeline {
    agent { label 'remote-web-server' }

    tools {
        nodejs 'node22' // must match your NodeJS plugin config name
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install') {
            steps {
                sh 'npm ci'
            }
        }

        stage('Build') {
            steps {
                sh 'npm run build'
                // Astro outputs to ./dist by default
            }
        }

        stage('Deploy') {
            steps {
                sshagent(credentials: [env.SSH_CRED_ID]) {
                    sh """
                    rsync -avz --delete \
                        --chmod=D755,F644 \
                        dist/ \
                        /var/www/red-team/
                        'sudo systemctl reload apache2'
                """
                }
            }
        }

    post {
        success {
            echo 'Astro site deployed successfully.'
        }
        failure {
            echo 'Build or deploy failed.'
        }
    }
}