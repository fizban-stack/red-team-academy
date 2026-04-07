pipeline {
    agent { label 'remote-web-server' } 

    stages {
        stage('Install Dependencies') {
            steps {
                sh 'cd jekyll-site && bundle install'
            }
        }
        stage('Build Site') {
            steps {
                sh 'cd jekyll-site && bundle exec jekyll build'
            }
        }
        stage('Deploy') {
            steps {
                sh '''
                rsync -av --delete \
                --no-perms \
                --no-owner \
                --no-group \
                --no-times \
                ./jekyll-site/_site/ /var/www/red-team-academy/
            '''
            }
        }
    }
}
