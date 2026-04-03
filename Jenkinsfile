pipeline {
    agent { label 'remote-web-server' }

    tools {
        nodejs 'node22'
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
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    rsync -avz --delete \
                        --chmod=D755,F644 \
                        dist/ \
                        /var/www/red-team/
                    sudo systemctl reload apache2
                '''
            }
        }

    } // <-- closes stages block (this was missing)

    post {
        success {
            echo 'Astro site deployed successfully.'
        }
        failure {
            echo 'Build or deploy failed.'
        }
    }
}