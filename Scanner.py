from toml import load
from shodan import Shodan
from argparse import ArgumentParser
from rich import console
from bs4 import BeautifulSoup
import os


def parseSqlLine(line: str) -> tuple[str]:
    splLine = line.split(' ')

    for index, value in enumerate(splLine):
        if value == ' ' or value == '':
            del splLine[index]

    fileName = splLine[0]
    sizeStr = splLine[2]

    if ':' in sizeStr or sizeStr == ' ' or sizeStr == '' or '-' in sizeStr:
        return (fileName, "NA")
    
    return (fileName, sizeStr)

parser = ArgumentParser(
    prog = 'ODMaster',
    description = 'Simple Open Directory Scanner For SQL Dbs',
)


parser.add_argument('-o', '--output', help = 'Output Directory')

console = console.Console()

args = parser.parse_args()

outputDirPath = args.output

config = load('Config.toml')
shodanConfig = config['Shodan']
scannerConfig = config['Scanner']

query = scannerConfig['query']

shodan = Shodan(key = shodanConfig['key'])

results = shodan.search_cursor(query)

dbOutput = open('DbUrls.txt', 'a')

console.print(f"([green]+[/green]) Scanning For Open Directories")

for result in results:

    try:

        ip = result['ip_str']
        port = result['port']

        dirPath = os.path.join(outputDirPath, ip)
        
        os.mkdir(dirPath)

        htmlSite = result['http']['html']
        bs4Html = BeautifulSoup(htmlSite, 'html.parser')

        htmlFile = open(os.path.join(dirPath, 'Site.html'), 'w', errors = 'ignore')
        infoFile = open(os.path.join(dirPath, 'Info.txt'), 'a', errors = 'ignore')

        htmlFile.write(bs4Html.prettify())
        htmlFile.close()
        
        infoFile.write('====================\n')
        infoFile.write(f'Host: {ip}:{port}\n')
        infoFile.write('====================\n')
        siteText = bs4Html.get_text().split('\n')
        
        for text in siteText:
            if '.sql' in text:
                clearText = text.strip().removeprefix(' ').removesuffix(' ')
                (fileName, fileSize) = parseSqlLine(clearText)

                console.print(f"([green]+[/green]) Found A SQL DB Of Size ([green]{fileSize}[/green]) ([underline white]{ip}:{port}[/underline white])")
                infoFile.write(f'{clearText}\n')
                dbOutput.write(f'{ip}/{fileName}\n')

        infoFile.write('====================\n')
        infoFile.close()


    except:
        continue

dbOutput.close()
console.print(f"([blue]*[/blue]) Done Scanning.")
