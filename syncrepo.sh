git remote add mirror ssh://git@gitlab.j114.army.mil:2200/ogs-automation/aap-import-export.git
git lfs fetch --all
git push -f mirror --mirror

