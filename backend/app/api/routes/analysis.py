"""Analyse hors ligne d'un fichier de capture depose par l'utilisateur.

Permet de rejouer une capture (PCAP) ou une extraction CICFlowMeter (CSV) a
travers le modele, sans dependre de la capture temps reel. C'est la voie la plus
proche du flux decrit dans le memoire, et la seule qui utilise les
caracteristiques calculees par le vrai CICFlowMeter lorsqu'on depose un CSV.
"""

from typing import Annotated, Any

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.api.deps import CurrentUser
from app.services.file_analysis import (
    EXTENSIONS_CSV,
    EXTENSIONS_PCAP,
    TAILLE_MAX_OCTETS,
    AnalyseError,
    analyser_fichier,
)

router = APIRouter(prefix="/analysis", tags=["Analyse de fichier"])


@router.get("/formats", summary="Formats de fichier acceptes")
def formats(_: CurrentUser) -> dict[str, Any]:
    """Decrit ce que l'interface peut proposer a l'utilisateur."""
    return {
        "pcap": sorted(EXTENSIONS_PCAP),
        "csv": sorted(EXTENSIONS_CSV),
        "max_size_mb": TAILLE_MAX_OCTETS // 1024 // 1024,
        "note": (
            "Un CSV CICFlowMeter donne les resultats les plus fideles : les 31 "
            "caracteristiques sont alors calculees par l'outil de reference, et "
            "non par l'agregation simplifiee appliquee aux PCAP."
        ),
    }


@router.post("/upload", summary="Analyser un fichier PCAP ou CSV CICFlowMeter")
async def upload(
    _: CurrentUser,
    file: Annotated[UploadFile, File(description="Capture .pcap/.pcapng ou CSV CICFlowMeter")],
) -> dict[str, Any]:
    """Classe tous les flux du fichier et retourne la synthese.

    Rien n'est enregistre en base : l'analyse est retournee a l'appelant, ce qui
    evite de polluer les indicateurs de surveillance avec des donnees rejouees.
    """
    contenu = await file.read()
    if not contenu:
        raise HTTPException(status_code=400, detail="Fichier vide.")

    try:
        return analyser_fichier(file.filename or "capture", contenu)
    except AnalyseError as exc:
        # Erreur fonctionnelle : le message est concu pour etre lu par l'utilisateur.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
